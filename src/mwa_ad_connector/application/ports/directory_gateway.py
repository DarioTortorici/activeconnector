"""Directory gateway port (abstract LDAP boundary).

The domain and application layers depend only on this protocol. The
concrete LDAP adapter (selected in a later step) implements it. Tests
use the in-memory fake under ``tests/fakes``.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.domain.objects import DirectoryGroup, DirectoryUser, OrganizationalUnit

AttributeMap = dict[str, str | list[str]]


class DirectoryGateway(Protocol):
    """Abstract asynchronous directory access boundary."""

    @property
    def source_dc(self) -> str:
        """Return the pinned DC name serving this gateway instance."""
        ...

    async def resolve_by_guid(self, guid: UUID) -> ObjectReference | None:
        """Resolve a GUID to its current object reference.

        Args:
            guid: Stable objectGUID to resolve.

        Returns:
            Current reference, or None when absent.
        """
        ...

    async def get_user(self, guid: UUID) -> DirectoryUser | None:
        """Fetch a typed user view by GUID.

        Args:
            guid: User objectGUID.

        Returns:
            User view or None when absent.
        """
        ...

    async def get_group(self, guid: UUID) -> DirectoryGroup | None:
        """Fetch a typed group view by GUID.

        Args:
            guid: Group objectGUID.

        Returns:
            Group view or None when absent.
        """
        ...

    async def get_ou(self, guid: UUID) -> OrganizationalUnit | None:
        """Fetch a typed OU view by GUID.

        Args:
            guid: OU objectGUID.

        Returns:
            OU view or None when absent.
        """
        ...

    async def search_users(
        self, query: str, page_size: int, page_token: str | None = None
    ) -> tuple[list[DirectoryUser], str | None]:
        """Search users with a predefined query profile.

        Args:
            query: Predefined query profile name (never raw LDAP).
            page_size: Maximum entries per page.
            page_token: Opaque continuation token.

        Returns:
            Tuple of (entries, next page token or None).
        """
        ...

    async def search_groups(
        self, query: str, page_size: int, page_token: str | None = None
    ) -> tuple[list[DirectoryGroup], str | None]:
        """Search groups with a predefined query profile.

        Args:
            query: Predefined query profile name (never raw LDAP).
            page_size: Maximum entries per page.
            page_token: Opaque continuation token.

        Returns:
            Tuple of (entries, next page token or None).
        """
        ...

    async def list_group_members(self, group_guid: UUID) -> list[UUID]:
        """List direct member GUIDs of a group.

        Args:
            group_guid: Group objectGUID.

        Returns:
            Direct member GUIDs.
        """
        ...

    async def add_group_member(self, group_guid: UUID, member_guid: UUID) -> None:
        """Add a member to a group.

        Args:
            group_guid: Target group GUID.
            member_guid: Member object GUID.
        """
        ...

    async def remove_group_member(self, group_guid: UUID, member_guid: UUID) -> None:
        """Remove a member from a group.

        Args:
            group_guid: Target group GUID.
            member_guid: Member object GUID.
        """
        ...

    async def unlock_account(self, user_guid: UUID) -> None:
        """Clear an account lockout.

        Args:
            user_guid: User objectGUID.
        """
        ...

    async def reset_password(self, user_guid: UUID, new_password: str) -> None:
        """Reset a password over a protected channel.

        The secret must never be logged, audited or retained.

        Args:
            user_guid: User objectGUID.
            new_password: New password value (handled as a protected secret).
        """
        ...

    async def set_pwd_last_set(self, user_guid: UUID, value: int) -> None:
        """Set pwdLastSet semantics (0 forces change, -1 clears).

        Args:
            user_guid: User objectGUID.
            value: pwdLastSet value to write.
        """
        ...

    async def set_account_enabled(self, user_guid: UUID, enabled: bool) -> None:
        """Enable or disable an account via userAccountControl bits.

        Args:
            user_guid: User objectGUID.
            enabled: Desired enabled state.
        """
        ...

    async def update_user_attributes(self, user_guid: UUID, attributes: AttributeMap) -> None:
        """Write allowlisted user attributes via minimal staged diff.

        Args:
            user_guid: User objectGUID.
            attributes: Allowlisted attribute map to apply.
        """
        ...

    async def create_user(self, parent_dn: str, attributes: AttributeMap) -> UUID:
        """Create a user under a managed OU.

        Args:
            parent_dn: Parent OU distinguished name.
            attributes: Allowlisted creation attributes.

        Returns:
            GUID of the created user.
        """
        ...

    async def rename_entry(self, guid: UUID, new_rdn: str) -> str:
        """Rename an entry (GUID unchanged).

        Args:
            guid: Entry objectGUID.
            new_rdn: New relative distinguished name.

        Returns:
            New distinguished name.
        """
        ...

    async def move_entry(self, guid: UUID, destination_dn: str) -> str:
        """Move an entry to another managed OU.

        Args:
            guid: Entry objectGUID.
            destination_dn: Destination parent DN.

        Returns:
            New distinguished name.
        """
        ...

    async def delete_entry(self, guid: UUID) -> None:
        """Delete a user or OU entry.

        Args:
            guid: Entry objectGUID.
        """
        ...

    async def create_group(self, parent_dn: str, attributes: AttributeMap) -> UUID:
        """Create a group under a managed OU.

        Args:
            parent_dn: Parent OU distinguished name.
            attributes: Allowlisted creation attributes.

        Returns:
            GUID of the created group.
        """
        ...

    async def update_group_attributes(self, group_guid: UUID, attributes: AttributeMap) -> None:
        """Write allowlisted group attributes.

        Args:
            group_guid: Group objectGUID.
            attributes: Allowlisted attribute map to apply.
        """
        ...

    async def delete_group(self, group_guid: UUID) -> None:
        """Delete a group.

        Args:
            group_guid: Group objectGUID.
        """
        ...

    async def create_ou(self, parent_dn: str, name: str) -> UUID:
        """Create a child OU.

        Args:
            parent_dn: Parent distinguished name.
            name: New OU name.

        Returns:
            GUID of the created OU.
        """
        ...

    async def delete_ou(self, guid: UUID) -> None:
        """Delete an empty, non-protected OU.

        Args:
            guid: OU objectGUID.
        """
        ...

    async def get_rootdse(self, domain_id: str) -> AttributeMap:
        """Read redacted RootDSE attributes for discovery.

        Args:
            domain_id: Domain boundary.

        Returns:
            Redacted RootDSE attribute map.
        """
        ...
