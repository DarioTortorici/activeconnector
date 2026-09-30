"""Read side of the LDAP adapter (resolve / get / search / members)."""

from __future__ import annotations

import logging
import ssl
from typing import Any
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import AttributeMap
from mwa_ad_connector.domain.enums import ObjectType
from mwa_ad_connector.domain.errors import DependencyUnavailableError, DomainError, ErrorCode
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.domain.objects import DirectoryGroup, DirectoryUser, OrganizationalUnit
from mwa_ad_connector.infrastructure.ldap.common import (
    _GROUP_ATTRS,
    _OU_ATTRS,
    _USER_ATTRS,
    _now,
)
from mwa_ad_connector.infrastructure.ldap.core import LdapAdapterCore
from mwa_ad_connector.infrastructure.ldap.mappings import map_entry_to_group, map_entry_to_ou, map_entry_to_user

logger = logging.getLogger(__name__)

_ALL_ATTRS = _USER_ATTRS + _GROUP_ATTRS + _OU_ATTRS


class LdapsCertificateError(DomainError):
    """LDAPS certificate validation failed for the pinned DC."""

    code = ErrorCode.LDAPS_CERTIFICATE_INVALID


class LdapAdapterReads(LdapAdapterCore):
    """Typed reads over the pinned DC."""

    async def ping(self) -> dict[str, Any]:
        """Check LDAP reachability by binding to the pinned DC.

        Returns:
            Redacted status dict (never contains hosts or credentials).

        Raises:
            LdapsCertificateError: When TLS validation fails.
            DependencyUnavailableError: When the bind fails for any other reason.
        """
        try:
            await self._manager.check_bind()
        except Exception as exc:  # noqa: BLE001 - normalized to domain errors.
            if isinstance(exc, ssl.SSLError) or isinstance(exc.__cause__, ssl.SSLError):
                raise LdapsCertificateError("LDAPS certificate validation failed") from exc
            raise DependencyUnavailableError("LDAP connectivity check failed") from exc
        return {"ok": True, "detail": "ldaps"}

    async def resolve_by_guid(self, guid: UUID) -> ObjectReference | None:
        """Resolve a GUID to its current reference (DN refreshed)."""
        entry = await self._entry_by_guid(guid, _ALL_ATTRS)
        if entry is None:
            return None
        attrs = entry.get("attributes", {})
        object_class = "user"
        if isinstance(attrs, dict):
            raw_classes = attrs.get("objectClass", [])
            classes = {str(c).lower() for c in (raw_classes if isinstance(raw_classes, list) else [raw_classes])}
            if "group" in classes:
                object_class = "group"
            elif "organizationalunit" in classes:
                object_class = "ou"
        object_type = {"user": ObjectType.USER, "group": ObjectType.GROUP, "ou": ObjectType.OU}[object_class]
        return ObjectReference(
            object_type=object_type,
            object_guid=guid,
            domain_id=self._domain_id,
            forest_id=self._forest_id,
            expected_dn=str(entry.get("dn", "")),
        )

    async def get_user(self, guid: UUID) -> DirectoryUser | None:
        """Fetch a typed user view by GUID."""
        entry = await self._entry_by_guid(guid, _ALL_ATTRS)
        if entry is None:
            return None
        try:
            return map_entry_to_user(entry, domain_id=self._domain_id, source_dc=self.source_dc, observed_at=_now())
        except ValueError:
            return None

    async def get_group(self, guid: UUID) -> DirectoryGroup | None:
        """Fetch a typed group view by GUID."""
        entry = await self._entry_by_guid(guid, _ALL_ATTRS)
        if entry is None:
            return None
        try:
            return map_entry_to_group(entry, domain_id=self._domain_id, source_dc=self.source_dc, observed_at=_now())
        except ValueError:
            return None

    async def get_ou(self, guid: UUID) -> OrganizationalUnit | None:
        """Fetch a typed OU view by GUID."""
        entry = await self._entry_by_guid(guid, _ALL_ATTRS)
        if entry is None:
            return None
        try:
            return map_entry_to_ou(entry, domain_id=self._domain_id, source_dc=self.source_dc, observed_at=_now())
        except ValueError:
            return None

    async def search_users(
        self, query: str, page_size: int, page_token: str | None = None
    ) -> tuple[list[DirectoryUser], str | None]:
        """Search users by prefix on sAMAccountName/UPN/mail with paging."""
        if page_size < 1:
            raise ValueError("page_size must be >= 1")
        profile, _, value = query.partition(":")
        needle = value if value else (profile if profile not in ("USER_BY_SAM", "USER_BY_UPN", "USER_BY_MAIL") else "")
        entries, next_token = await self._paged(self._prefix_filter("user", needle), _USER_ATTRS, page_size, page_token)
        users: list[DirectoryUser] = []
        for raw in entries:
            try:
                users.append(
                    map_entry_to_user(raw, domain_id=self._domain_id, source_dc=self.source_dc, observed_at=_now())
                )
            except ValueError as exc:
                attrs = raw.get("attributes")
                keys = sorted(str(key) for key in attrs) if isinstance(attrs, dict) else []
                logger.warning("skipping unmappable user entry: %s | attributes=%s", exc, keys)
        return users, next_token

    async def search_groups(
        self, query: str, page_size: int, page_token: str | None = None
    ) -> tuple[list[DirectoryGroup], str | None]:
        """Search groups by prefix on sAMAccountName/name with paging."""
        if page_size < 1:
            raise ValueError("page_size must be >= 1")
        profile, _, value = query.partition(":")
        needle = value if value else (profile if profile != "GROUP_BY_NAME" else "")
        entries, next_token = await self._paged(
            self._prefix_filter("group", needle), _GROUP_ATTRS, page_size, page_token
        )
        groups: list[DirectoryGroup] = []
        for raw in entries:
            try:
                groups.append(
                    map_entry_to_group(raw, domain_id=self._domain_id, source_dc=self.source_dc, observed_at=_now())
                )
            except ValueError as exc:
                attrs = raw.get("attributes")
                keys = sorted(str(key) for key in attrs) if isinstance(attrs, dict) else []
                logger.warning("skipping unmappable group entry: %s | attributes=%s", exc, keys)
        return groups, next_token

    async def lookup_by_dn(self, dn: str) -> dict[str, object] | None:
        """Base-object lookup by DN (extra helper for DN identifiers)."""
        return await self._lookup_raw(dn, _ALL_ATTRS)

    async def list_group_members(self, group_guid: UUID) -> list[UUID]:
        """List direct member GUIDs (unresolvable DNs are skipped)."""
        from mwa_ad_connector.infrastructure.ldap.common import _GUID_ATTRS  # noqa: PLC0415

        group_dn = await self._dn_for_guid(group_guid, _GUID_ATTRS)
        entry = await self._lookup_raw(group_dn, ["member"])
        if entry is None:
            raise LookupError(f"TARGET_NOT_FOUND: {group_guid}")
        attrs = entry.get("attributes")
        if not isinstance(attrs, dict):
            raise TypeError("LDAP entry attributes must be a mapping")
        raw_members = attrs.get("member", [])
        dns = [str(m) for m in (raw_members if isinstance(raw_members, list) else [raw_members])]
        guids: list[UUID] = []
        for dn in dns:
            guid = await self._guid_for_dn(dn, _GUID_ATTRS)
            if guid is not None:
                guids.append(guid)
            else:
                logger.warning("skipping unresolvable member dn")
        return sorted(guids)

    async def get_rootdse(self, domain_id: str) -> AttributeMap:
        """Read redacted RootDSE attributes for discovery."""
        from mwa_ad_connector.infrastructure.ldap.discovery import get_rootdse as _fetch  # noqa: PLC0415

        _ = domain_id
        root = await _fetch(self._manager)
        dumped: dict[str, object] = root.model_dump()
        out: AttributeMap = {}
        for key, value in dumped.items():
            if key == "dns_hostname":
                out[key] = "***REDACTED***"
            elif isinstance(value, list):
                out[key] = [str(v) for v in value]
            else:
                out[key] = str(value)
        return out
