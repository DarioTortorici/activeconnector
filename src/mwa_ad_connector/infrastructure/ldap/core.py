"""Pinned-DC core for the LDAP adapter (raw helpers, DN refresh, paging)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from mwa_ad_connector.infrastructure.ldap.common import _check, _entry_to_dict
from mwa_ad_connector.infrastructure.ldap.connection import LdapConnectionManager
from mwa_ad_connector.infrastructure.ldap.filters import build_guid_filter, escape_filter_value, validate_dn_syntax

_PAGED_RESULT_OID = "1.2.840.113556.1.4.319"


def _normalize_paged_entry(item: dict[str, Any]) -> dict[str, object]:
    """Normalize one paged-search response dict to the entry shape.

    ldap3 ``paged_search`` with ``generator=True`` yields raw response dicts
    (``dn``/``attributes``/``type``), not ``Entry`` objects. Attribute maps are
    ``CaseInsensitiveDict`` instances (not ``dict`` subclasses), so mappings
    must be checked against ``collections.abc.Mapping``.

    Args:
        item: Raw response item from a paged search.

    Returns:
        Mapping with ``dn`` and ``attributes`` keys.
    """
    attrs = item.get("attributes")
    if not isinstance(attrs, Mapping):
        raw = item.get("raw_attributes")
        attrs = raw if isinstance(raw, Mapping) else {}
    return {"dn": str(item.get("dn", "")), "attributes": {str(k): v for k, v in attrs.items()}}


def _paged_cookie(conn: Any) -> bytes | None:
    """Extract the paging cookie from the last LDAP result, if any."""
    controls = dict(conn.result).get("controls", {})
    try:
        value = controls[_PAGED_RESULT_OID]["value"]["cookie"]
    except (KeyError, TypeError):
        return None
    if isinstance(value, (bytes, bytearray)) and value:
        return bytes(value)
    return None


class LdapAdapterCore:
    """Pinned-DC connection core shared by read and write mixins.

    Args:
        manager: Pinned-DC connection manager.
        base_dn: Search base DN.
        domain_id: Owning domain id.
        forest_id: Owning forest id.
    """

    def __init__(self, manager: LdapConnectionManager, base_dn: str, domain_id: str, forest_id: str = "") -> None:
        self._manager = manager
        self._base_dn = validate_dn_syntax(base_dn)
        self._domain_id = domain_id
        self._forest_id = forest_id

    @property
    def source_dc(self) -> str:
        """Return the pinned DC serving this instance."""
        return self._manager.pinned_host

    @property
    def is_secure_transport(self) -> bool:
        """Return True when LDAPS is enforced (required for password writes)."""
        return self._manager.is_ldaps_enforced

    async def _search_raw(self, search_filter: str, attributes: list[str]) -> list[dict[str, object]]:
        from ldap3 import SUBTREE  # noqa: PLC0415

        def _op(conn: Any) -> list[dict[str, object]]:
            found = conn.search(self._base_dn, search_filter, search_scope=SUBTREE, attributes=attributes)
            _check(conn, "search")
            return [_entry_to_dict(e) for e in conn.entries] if found else []

        entries, _ = await self._manager.execute(_op)
        return entries

    async def _lookup_raw(self, dn: str, attributes: list[str]) -> dict[str, object] | None:
        from ldap3 import BASE  # noqa: PLC0415

        def _op(conn: Any) -> dict[str, object] | None:
            ok = conn.search(validate_dn_syntax(dn), "(objectClass=*)", search_scope=BASE, attributes=attributes)
            _check(conn, "lookup")
            if not ok or not list(conn.entries):
                return None
            return _entry_to_dict(list(conn.entries)[0])

        entry, _ = await self._manager.execute(_op)
        return entry

    async def _entry_by_guid(self, guid: UUID, attributes: list[str]) -> dict[str, object] | None:
        entries = await self._search_raw(build_guid_filter(guid), attributes)
        if len(entries) > 1:
            raise RuntimeError("AMBIGUOUS_TARGET: multiple entries share one GUID")
        return entries[0] if entries else None

    async def _dn_for_guid(self, guid: UUID, attributes: list[str]) -> str:
        """Refresh the current DN for a GUID immediately before a mutation."""
        from mwa_ad_connector.infrastructure.ldap.common import _GUID_ATTRS  # noqa: PLC0415

        entry = await self._entry_by_guid(guid, attributes or _GUID_ATTRS)
        if entry is None:
            raise LookupError(f"TARGET_NOT_FOUND: {guid}")
        return str(entry.get("dn", ""))

    async def _guid_for_dn(self, dn: str, attributes: list[str]) -> UUID | None:
        from mwa_ad_connector.infrastructure.ldap.mappings import guid_bytes_le_to_uuid  # noqa: PLC0415

        entry = await self._lookup_raw(dn, attributes)
        if entry is None:
            return None
        attrs = entry.get("attributes")
        if not isinstance(attrs, dict):
            return None
        raw = attrs.get("objectGUID")
        blob = raw[0] if isinstance(raw, list) and raw else raw
        if isinstance(blob, str):
            blob = blob.encode("latin1")
        if not isinstance(blob, (bytes, bytearray)):
            return None
        return guid_bytes_le_to_uuid(bytes(blob))

    async def _modify_raw(self, dn: str, changes: dict[str, list[tuple[str, list[Any]]]], operation: str) -> None:
        def _op(conn: Any) -> None:
            conn.modify(validate_dn_syntax(dn), changes)
            _check(conn, operation)

        await self._manager.execute(_op)

    def _prefix_filter(self, object_class: str, value: str) -> str:
        esc = escape_filter_value(value)
        if object_class == "group":
            return f"(&(objectClass=group)(|(sAMAccountName={esc}*)(name={esc}*)))"
        return f"(&(objectClass=user)(|(sAMAccountName={esc}*)(userPrincipalName={esc}*)(mail={esc}*)))"

    async def _paged(
        self, search_filter: str, attributes: list[str], page_size: int, page_token: str | None
    ) -> tuple[list[dict[str, object]], str | None]:
        """Run a cookie-paged search and return a slice plus the next offset.

        The token is an opaque string carrying the entry offset of the slice
        start; the returned token is the offset of the next slice.

        Args:
            search_filter: Prebuilt LDAP filter (never raw caller input).
            attributes: Requested attributes.
            page_size: Maximum entries per slice.
            page_token: Offset token from a previous call, or None.

        Returns:
            Tuple of (entry dicts for this slice, next offset token or None).
        """
        from ldap3 import SUBTREE  # noqa: PLC0415

        start = int(page_token) if page_token else 0

        def _op(conn: Any) -> tuple[list[dict[str, object]], str | None]:
            collected: list[dict[str, object]] = []
            seen = 0
            more = False
            cookie: bytes | None = None
            while True:
                conn.search(
                    self._base_dn,
                    search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes,
                    paged_size=page_size,
                    paged_cookie=cookie,
                )
                _check(conn, "search")
                page_entries = [item for item in conn.response if item.get("type") == "searchResEntry"]
                for item in page_entries:
                    if len(collected) >= page_size:
                        more = True
                        break
                    if seen >= start:
                        collected.append(_normalize_paged_entry(item))
                    seen += 1
                if more or not page_entries:
                    break
                cookie = _paged_cookie(conn)
                if not cookie:
                    break
            next_token = str(start + len(collected)) if more else None
            return collected, next_token

        entries, _ = await self._manager.execute(_op)
        return entries
