"""OU lifecycle service (create / rename / move / delete require_empty)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.domain.errors import DomainError, ErrorCode, TargetNotFoundError, VerificationFailedError


class OuNotEmptyError(DomainError):
    """OU still has children and require_empty is set."""

    code = ErrorCode.LDAP_CONSTRAINT_VIOLATION


@dataclass(frozen=True)
class OuOutcome:
    """OU mutation result.

    Attributes:
        disposition: APPLIED (OUs have no NO_OP path).
        ou_guid: Target OU GUID (new GUID for create).
        dn_before: DN before the operation.
        dn_after: DN after the operation.
        changed_fields: Logical changed fields.
        source_dc: Committing DC.
        verified: Same-DC verification flag.
    """

    disposition: str
    ou_guid: UUID
    dn_before: str
    dn_after: str
    changed_fields: tuple[str, ...]
    source_dc: str
    verified: bool


class OuService:
    """Managed-scope OU mutations; delete requires an empty OU.

    Args:
        gateway: Canonical directory gateway.
    """

    def __init__(self, gateway: DirectoryGateway) -> None:
        self._gateway = gateway

    async def create(self, parent_dn: str, name: str) -> OuOutcome:
        """Create a child OU.

        Args:
            parent_dn: Parent container DN.
            name: OU name.

        Returns:
            OuOutcome with the new GUID.
        """
        guid = await self._gateway.create_ou(parent_dn, name)
        created = await self._gateway.get_ou(guid)
        if created is None:
            raise VerificationFailedError("created OU not readable")
        return OuOutcome("APPLIED", guid, "", created.distinguished_name, ("create",), self._gateway.source_dc, True)

    async def rename(self, ou_guid: UUID, new_rdn: str) -> OuOutcome:
        """Rename an OU with GUID invariance check.

        Args:
            ou_guid: Target OU GUID.
            new_rdn: New RDN (e.g. ``OU=New``).

        Returns:
            OuOutcome.
        """
        before = await self._gateway.get_ou(ou_guid)
        if before is None:
            raise TargetNotFoundError(f"target not found: {ou_guid}")
        new_dn = await self._gateway.rename_entry(ou_guid, new_rdn)
        after = await self._gateway.get_ou(ou_guid)
        if after is None or after.distinguished_name != new_dn:
            raise VerificationFailedError("OU rename verification failed")
        return OuOutcome(
            "APPLIED",
            ou_guid,
            before.distinguished_name,
            after.distinguished_name,
            ("rdn",),
            self._gateway.source_dc,
            True,
        )

    async def move(self, ou_guid: UUID, destination_parent_dn: str) -> OuOutcome:
        """Move an OU within the managed scope.

        Args:
            ou_guid: Target OU GUID.
            destination_parent_dn: Destination parent DN.

        Returns:
            OuOutcome.
        """
        before = await self._gateway.get_ou(ou_guid)
        if before is None:
            raise TargetNotFoundError(f"target not found: {ou_guid}")
        await self._gateway.move_entry(ou_guid, destination_parent_dn)
        after = await self._gateway.get_ou(ou_guid)
        if after is None or after.object_guid != ou_guid:
            raise VerificationFailedError("OU move verification failed")
        return OuOutcome(
            "APPLIED",
            ou_guid,
            before.distinguished_name,
            after.distinguished_name,
            ("move",),
            self._gateway.source_dc,
            True,
        )

    async def delete(self, ou_guid: UUID, require_empty: bool = True) -> OuOutcome:
        """Delete an OU (empty-only unless explicitly overridden).

        Args:
            ou_guid: Target OU GUID.
            require_empty: When True, refuse OUs reporting children.

        Returns:
            OuOutcome after absence verification.
        """
        before = await self._gateway.get_ou(ou_guid)
        if before is None:
            raise TargetNotFoundError(f"target not found: {ou_guid}")
        if require_empty and before.child_count > 0:
            raise OuNotEmptyError("OU not empty")
        await self._gateway.delete_ou(ou_guid)
        if await self._gateway.get_ou(ou_guid) is not None:
            raise VerificationFailedError("OU still present after delete")
        return OuOutcome("APPLIED", ou_guid, before.distinguished_name, "", ("delete",), self._gateway.source_dc, True)
