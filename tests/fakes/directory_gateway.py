"""In-memory fake DirectoryGateway for unit/contract tests.

Deterministic, no network. A fixed ``source_dc`` name enables DC
pinning assertions. Entries live in ``guid -> _FakeEntry`` dicts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final
from uuid import UUID, uuid4

from mwa_ad_connector.domain.enums import IdentifierType, ObjectType
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.domain.objects import DirectoryGroup, DirectoryUser, OrganizationalUnit

logger = logging.getLogger(__name__)

FAKE_DC_NAME = "dc-fake-01.lab.local"
_MIN_PAGE_SIZE: Final[int] = 1


@dataclass
class _FakeEntry:
    """Internal fake directory entry."""

    guid: UUID
    dn: str
    object_type: ObjectType
    domain_id: str
    forest_id: str
    sam_account_name: str = ""
    user_principal_name: str | None = None
    display_name: str | None = None
    name: str | None = None
    enabled: bool = True
    locked: bool = False
    group_scope: str = "Global"
    group_category: str = "Security"
    is_privileged: bool = False
    member_guids: set[UUID] = field(default_factory=set)
    attributes: dict[str, str | list[str]] = field(default_factory=dict)
    version_token: str = "v1"  # noqa: S105 -- opaque concurrency marker, not a credential


class FakeDirectoryGateway:
    """In-memory DirectoryGateway implementation for tests.

    Attributes:
        dc_name: Fixed DC name reported as source_dc for pinning tests.
    """

    def __init__(self, dc_name: str = FAKE_DC_NAME, domain_id: str = "domain-lab") -> None:
        """Initialize an empty fake gateway.

        Args:
            dc_name: Fixed DC name to report.
            domain_id: Default domain for seeded entries.
        """
        self._dc_name = dc_name
        self._default_domain = domain_id
        self._entries: dict[UUID, _FakeEntry] = {}
        self.password_resets: list[UUID] = []

    @property
    def source_dc(self) -> str:
        """Return the fixed fake DC name."""
        return self._dc_name

    async def ping(self) -> dict[str, Any]:
        """Report reachability without any network access."""
        return {"ok": True, "detail": "fake"}

    def seed_user(
        self,
        guid: UUID | None = None,
        sam: str = "jdoe",
        dn: str = "CN=jdoe,OU=Users,DC=lab,DC=local",
    ) -> UUID:
        """Seed a user entry and return its GUID.

        Args:
            guid: Optional fixed GUID (random when omitted).
            sam: sAMAccountName value.
            dn: Distinguished name value.

        Returns:
            Seeded user GUID.
        """
        gid = guid or uuid4()
        self._entries[gid] = _FakeEntry(
            guid=gid,
            dn=dn,
            object_type=ObjectType.USER,
            domain_id=self._default_domain,
            forest_id="forest-lab",
            sam_account_name=sam,
            user_principal_name=f"{sam}@lab.local",
            display_name=sam,
        )
        return gid

    def seed_group(
        self, guid: UUID | None = None, name: str = "grp", dn: str = "CN=grp,OU=Groups,DC=lab,DC=local"
    ) -> UUID:
        """Seed a group entry and return its GUID.

        Args:
            guid: Optional fixed GUID.
            name: Group name.
            dn: Distinguished name value.

        Returns:
            Seeded group GUID.
        """
        gid = guid or uuid4()
        self._entries[gid] = _FakeEntry(
            guid=gid,
            dn=dn,
            object_type=ObjectType.GROUP,
            domain_id=self._default_domain,
            forest_id="forest-lab",
            sam_account_name=name,
            name=name,
        )
        return gid

    def _require(self, guid: UUID) -> _FakeEntry:
        """Fetch an entry or raise a lookup error.

        Args:
            guid: Entry GUID.

        Returns:
            Fake entry.

        Raises:
            KeyError: When the GUID is unknown.
        """
        try:
            return self._entries[guid]
        except KeyError as exc:
            raise KeyError(f"Unknown guid: {guid}") from exc

    def _observed_at(self) -> datetime:
        """Return a timezone-aware observation timestamp.

        Returns:
            Current UTC timestamp.
        """
        return datetime.now(timezone.utc)

    async def resolve_by_guid(self, guid: UUID) -> ObjectReference | None:
        """Resolve a GUID to its current reference, or None when absent."""
        entry = self._entries.get(guid)
        if entry is None:
            return None
        id_kind = IdentifierType.SAM_ACCOUNT_NAME if entry.object_type != ObjectType.OU else None
        id_value = entry.sam_account_name or entry.name if id_kind else None
        return ObjectReference(
            object_type=entry.object_type,
            object_guid=entry.guid,
            identifier_type=id_kind,
            identifier_value=id_value,
            domain_id=entry.domain_id,
            forest_id=entry.forest_id,
            expected_dn=None,
        )

    async def get_user(self, guid: UUID) -> DirectoryUser | None:
        """Fetch a user view by GUID, or None when absent/mismatched."""
        entry = self._entries.get(guid)
        if entry is None or entry.object_type != ObjectType.USER:
            return None
        return DirectoryUser(
            object_guid=entry.guid,
            distinguished_name=entry.dn,
            domain_id=entry.domain_id,
            sam_account_name=entry.sam_account_name,
            user_principal_name=entry.user_principal_name,
            display_name=entry.display_name,
            enabled=entry.enabled,
            locked=entry.locked,
            pwd_last_set=None,
            member_of_guids=[],
            attributes=dict(entry.attributes),
            version_token=entry.version_token,
            source_dc=self._dc_name,
            observed_at=self._observed_at(),
        )

    async def get_group(self, guid: UUID) -> DirectoryGroup | None:
        """Fetch a group view by GUID, or None when absent/mismatched."""
        entry = self._entries.get(guid)
        if entry is None or entry.object_type != ObjectType.GROUP:
            return None
        return DirectoryGroup(
            object_guid=entry.guid,
            distinguished_name=entry.dn,
            domain_id=entry.domain_id,
            sam_account_name=entry.sam_account_name,
            name=entry.name or entry.sam_account_name,
            group_scope=entry.group_scope,
            group_category=entry.group_category,
            member_guids=sorted(entry.member_guids),
            is_privileged=entry.is_privileged,
            protection_reasons=[],
            version_token=entry.version_token,
            source_dc=self._dc_name,
            observed_at=self._observed_at(),
        )

    async def get_ou(self, guid: UUID) -> OrganizationalUnit | None:
        """Fetch an OU view by GUID, or None when absent/mismatched."""
        entry = self._entries.get(guid)
        if entry is None or entry.object_type != ObjectType.OU:
            return None
        return OrganizationalUnit(
            object_guid=entry.guid,
            distinguished_name=entry.dn,
            domain_id=entry.domain_id,
            name=entry.name or "ou",
            parent_dn="DC=lab,DC=local",
            child_count=0,
            version_token=entry.version_token,
            source_dc=self._dc_name,
            observed_at=self._observed_at(),
        )

    async def search_users(
        self, query: str, page_size: int, page_token: str | None = None
    ) -> tuple[list[DirectoryUser], str | None]:
        """Search seeded users (query matched as substring on sAMAccountName)."""
        if page_size < _MIN_PAGE_SIZE:
            raise ValueError("page_size must be >= 1")
        matched = [
            e for e in self._entries.values() if e.object_type == ObjectType.USER and query in e.sam_account_name
        ]
        start = int(page_token) if page_token else 0
        chunk = matched[start : start + page_size]
        result: list[DirectoryUser] = []
        for entry in chunk:
            user = await self.get_user(entry.guid)
            if user is not None:
                result.append(user)
        next_token = str(start + page_size) if start + page_size < len(matched) else None
        return result, next_token

    async def search_groups(
        self, query: str, page_size: int, page_token: str | None = None
    ) -> tuple[list[DirectoryGroup], str | None]:
        """Search seeded groups (query matched as substring on name)."""
        if page_size < _MIN_PAGE_SIZE:
            raise ValueError("page_size must be >= 1")
        matched = [
            e
            for e in self._entries.values()
            if e.object_type == ObjectType.GROUP and query in (e.name or e.sam_account_name)
        ]
        start = int(page_token) if page_token else 0
        chunk = matched[start : start + page_size]
        result: list[DirectoryGroup] = []
        for entry in chunk:
            group = await self.get_group(entry.guid)
            if group is not None:
                result.append(group)
        next_token = str(start + page_size) if start + page_size < len(matched) else None
        return result, next_token

    async def list_group_members(self, group_guid: UUID) -> list[UUID]:
        """List direct member GUIDs of a group."""
        return sorted(self._require(group_guid).member_guids)

    async def add_group_member(self, group_guid: UUID, member_guid: UUID) -> None:
        """Add a member to a group (idempotent)."""
        group = self._require(group_guid)
        self._require(member_guid)
        group.member_guids.add(member_guid)
        logger.debug("fake_member_added", extra={"group": str(group_guid)})

    async def remove_group_member(self, group_guid: UUID, member_guid: UUID) -> None:
        """Remove a member from a group (idempotent)."""
        group = self._require(group_guid)
        group.member_guids.discard(member_guid)

    async def unlock_account(self, user_guid: UUID) -> None:
        """Clear the locked flag on a user."""
        self._require(user_guid).locked = False

    async def reset_password(self, user_guid: UUID, new_password: str) -> None:
        """Record a password reset without storing the secret."""
        self._require(user_guid)
        _ = new_password
        self.password_resets.append(user_guid)

    async def set_pwd_last_set(self, user_guid: UUID, value: int) -> None:
        """Store pwdLastSet intent as a redacted attribute marker."""
        entry = self._require(user_guid)
        entry.attributes["pwdLastSet"] = str(value)

    async def set_account_enabled(self, user_guid: UUID, enabled: bool) -> None:
        """Set the enabled flag on a user."""
        self._require(user_guid).enabled = enabled

    async def update_user_attributes(self, user_guid: UUID, attributes: dict[str, str | list[str]]) -> None:
        """Apply an allowlisted attribute map to a user."""
        entry = self._require(user_guid)
        entry.attributes.update(attributes)

    async def create_user(self, parent_dn: str, attributes: dict[str, str | list[str]]) -> UUID:
        """Create a user entry under a parent DN."""
        gid = uuid4()
        sam_value = attributes.get("sAMAccountName", "newuser")
        sam = sam_value[0] if isinstance(sam_value, list) else sam_value
        self._entries[gid] = _FakeEntry(
            guid=gid,
            dn=f"CN={sam},{parent_dn}",
            object_type=ObjectType.USER,
            domain_id=self._default_domain,
            forest_id="forest-lab",
            sam_account_name=sam,
            attributes=dict(attributes),
        )
        return gid

    async def rename_entry(self, guid: UUID, new_rdn: str) -> str:
        """Rename an entry, preserving its GUID."""
        entry = self._require(guid)
        parent = entry.dn.split(",", 1)[1] if "," in entry.dn else "DC=lab,DC=local"
        entry.dn = f"{new_rdn},{parent}"
        return entry.dn

    async def move_entry(self, guid: UUID, destination_dn: str) -> str:
        """Move an entry under a new parent DN."""
        entry = self._require(guid)
        rdn = entry.dn.split(",", 1)[0]
        entry.dn = f"{rdn},{destination_dn}"
        return entry.dn

    async def delete_entry(self, guid: UUID) -> None:
        """Delete an entry by GUID."""
        self._require(guid)
        del self._entries[guid]

    async def create_group(self, parent_dn: str, attributes: dict[str, str | list[str]]) -> UUID:
        """Create a group entry under a parent DN."""
        gid = uuid4()
        name_value = attributes.get("name", "newgroup")
        name = name_value[0] if isinstance(name_value, list) else name_value
        self._entries[gid] = _FakeEntry(
            guid=gid,
            dn=f"CN={name},{parent_dn}",
            object_type=ObjectType.GROUP,
            domain_id=self._default_domain,
            forest_id="forest-lab",
            sam_account_name=name,
            name=name,
            attributes=dict(attributes),
        )
        return gid

    async def update_group_attributes(self, group_guid: UUID, attributes: dict[str, str | list[str]]) -> None:
        """Apply an allowlisted attribute map to a group."""
        entry = self._require(group_guid)
        entry.attributes.update(attributes)

    async def delete_group(self, group_guid: UUID) -> None:
        """Delete a group by GUID."""
        self._require(group_guid)
        del self._entries[group_guid]

    async def create_ou(self, parent_dn: str, name: str) -> UUID:
        """Create an OU entry under a parent DN."""
        gid = uuid4()
        self._entries[gid] = _FakeEntry(
            guid=gid,
            dn=f"OU={name},{parent_dn}",
            object_type=ObjectType.OU,
            domain_id=self._default_domain,
            forest_id="forest-lab",
            name=name,
        )
        return gid

    async def delete_ou(self, guid: UUID) -> None:
        """Delete an OU by GUID."""
        self._require(guid)
        del self._entries[guid]

    async def get_rootdse(self, domain_id: str) -> dict[str, str | list[str]]:
        """Return a canned redacted RootDSE map."""
        _ = domain_id
        return {"namingContexts": ["DC=lab,DC=local"], "dnsHostName": "***REDACTED***"}
