"""Group lifecycle service (create / update / rename / move / delete)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import AttributeMap, DirectoryGateway
from mwa_ad_connector.domain.errors import (
    ConcurrentModificationError,
    DomainError,
    ErrorCode,
    RequestInvalidError,
    TargetNotFoundError,
    VerificationFailedError,
)


class GroupNotEmptyError(DomainError):
    """Group still has members."""

    code = ErrorCode.LDAP_CONSTRAINT_VIOLATION


# Interim default group attribute allowlist (mirrors the LDAP adapter).
# Owner after Step 7: policy engine.
_DEFAULT_GROUP_ALLOWLIST = frozenset({"description", "mail"})


@dataclass(frozen=True)
class GroupOutcome:
    """Group mutation result.

    Attributes:
        disposition: APPLIED or NO_OP.
        group_guid: Target GUID.
        dn_before: DN before the operation.
        dn_after: DN after the operation.
        changed_fields: Logical changed fields.
        source_dc: Committing DC.
        verified: Same-DC verification flag.
    """

    disposition: str
    group_guid: UUID
    dn_before: str
    dn_after: str
    changed_fields: tuple[str, ...]
    source_dc: str
    verified: bool


class GroupService:
    """Allowlisted group mutations.

    Args:
        gateway: Canonical directory gateway.
    """

    def __init__(self, gateway: DirectoryGateway) -> None:
        self._gateway = gateway

    def _allowlist(self) -> frozenset[str]:
        fn = getattr(self._gateway, "group_allowlist", None)
        if callable(fn):
            return frozenset(fn())
        # Interim default until the Step 7 policy engine owns attribute allowlists.
        return _DEFAULT_GROUP_ALLOWLIST

    async def create(self, parent_dn: str, attributes: AttributeMap) -> GroupOutcome:
        """Create a group under a managed parent.

        Args:
            parent_dn: Parent OU DN.
            attributes: Allowlisted creation attributes.

        Returns:
            GroupOutcome with the new GUID.
        """
        guid = await self._gateway.create_group(parent_dn, attributes)
        created = await self._gateway.get_group(guid)
        if created is None:
            raise VerificationFailedError("created group not readable")
        return GroupOutcome("APPLIED", guid, "", created.distinguished_name, ("create",), self._gateway.source_dc, True)

    async def update_attributes(
        self, group_guid: UUID, attributes: AttributeMap, expected_version: str | None = None
    ) -> GroupOutcome:
        """Apply an allowlisted group attribute diff.

        Args:
            group_guid: Target group GUID.
            attributes: Desired values.
            expected_version: Concurrency token.

        Returns:
            GroupOutcome.
        """
        group = await self._gateway.get_group(group_guid)
        if group is None:
            raise TargetNotFoundError(f"target not found: {group_guid}")
        if expected_version is not None and expected_version != group.version_token:
            raise ConcurrentModificationError("group changed since expected_version")
        allowlist = self._allowlist()
        for name in attributes:
            if name.lower() not in allowlist:
                raise RequestInvalidError(f"attribute not allowlisted: {name}")
        await self._gateway.update_group_attributes(group_guid, attributes)
        return GroupOutcome(
            "APPLIED",
            group_guid,
            group.distinguished_name,
            group.distinguished_name,
            tuple(sorted(attributes)),
            self._gateway.source_dc,
            True,
        )

    async def rename(self, group_guid: UUID, new_rdn: str) -> GroupOutcome:
        """Rename a group with GUID invariance check.

        Args:
            group_guid: Target group GUID.
            new_rdn: New RDN.

        Returns:
            GroupOutcome.
        """
        group = await self._gateway.get_group(group_guid)
        if group is None:
            raise TargetNotFoundError(f"target not found: {group_guid}")
        new_dn = await self._gateway.rename_entry(group_guid, new_rdn)
        after = await self._gateway.get_group(group_guid)
        if after is None or after.distinguished_name != new_dn:
            raise VerificationFailedError("rename verification failed")
        return GroupOutcome(
            "APPLIED",
            group_guid,
            group.distinguished_name,
            after.distinguished_name,
            ("rdn",),
            self._gateway.source_dc,
            True,
        )

    async def move(self, group_guid: UUID, destination_ou_dn: str) -> GroupOutcome:
        """Move a group between managed OUs.

        Args:
            group_guid: Target group GUID.
            destination_ou_dn: Destination container DN.

        Returns:
            GroupOutcome.
        """
        group = await self._gateway.get_group(group_guid)
        if group is None:
            raise TargetNotFoundError(f"target not found: {group_guid}")
        await self._gateway.move_entry(group_guid, destination_ou_dn)
        after = await self._gateway.get_group(group_guid)
        if after is None or after.object_guid != group_guid:
            raise VerificationFailedError("move verification failed")
        return GroupOutcome(
            "APPLIED",
            group_guid,
            group.distinguished_name,
            after.distinguished_name,
            ("move",),
            self._gateway.source_dc,
            True,
        )

    async def delete(self, group_guid: UUID) -> GroupOutcome:
        """Delete an empty group.

        Args:
            group_guid: Target group GUID.

        Returns:
            GroupOutcome after absence verification.
        """
        group = await self._gateway.get_group(group_guid)
        if group is None:
            raise TargetNotFoundError(f"target not found: {group_guid}")
        if await self._gateway.list_group_members(group_guid):
            raise GroupNotEmptyError("group not empty")
        await self._gateway.delete_group(group_guid)
        if await self._gateway.get_group(group_guid) is not None:
            raise VerificationFailedError("group still present after delete")
        return GroupOutcome(
            "APPLIED", group_guid, group.distinguished_name, "", ("delete",), self._gateway.source_dc, True
        )
