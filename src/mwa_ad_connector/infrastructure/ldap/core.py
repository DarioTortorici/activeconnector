"""Pinned-DC core for the LDAP adapter (raw helpers, DN refresh, paging)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from mwa_ad_connector.infrastructure.ldap.common import _check, _entry_to_dict
from mwa_ad_connector.infrastructure.ldap.connection import LdapConnectionManager
from mwa_ad_connector.infrastructure.ldap.error_mapping import map_ldap_result
from mwa_ad_connector.infrastructure.ldap.filters import build_guid_filter, escape_filter_value, validate_dn_syntax


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
        from ldap3 import SUBTREE  # noqa: PLC0415

        wanted = int(page_token) if page_token else 0

        def _op(conn: Any) -> tuple[list[dict[str, object]], str | None]:
            gen = conn.extend.standard.paged_search(
                self._base_dn, search_filter, SUBTREE, attributes=attributes, paged_size=page_size, generator=True
            )
            index = 0
            for entry in gen:
                if not getattr(entry, "entry_dn", None):
                    result_code = int(dict(conn.result).get("result", 0))
                    if result_code != 0:
                        mapped = map_ldap_result(result_code, str(dict(conn.result)), "search")
                        raise RuntimeError(f"{mapped.code}: {mapped.remediation}")
                    continue
                if index == wanted:
                    page = [_entry_to_dict(entry)]
                    for more in gen:
                        if not getattr(more, "entry_dn", None):
                            break
                        page.append(_entry_to_dict(more))
                        if len(page) >= page_size:
                            break
                    cookie = (
                        conn.result.get("controls", {})
                        .get("1.2.840.113556.1.4.319", {})
                        .get("value", {})
                        .get("cookie", b"")
                    )
                    return page, (str(wanted + 1) if cookie else None)
                index += 1
            return [], None

        entries, _ = await self._manager.execute(_op)
        return entries
