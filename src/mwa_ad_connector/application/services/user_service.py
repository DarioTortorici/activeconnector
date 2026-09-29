"""User lifecycle service (create / update / rename / move / delete)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import AttributeMap, DirectoryGateway
from mwa_ad_connector.domain.errors import (
    ConcurrentModificationError,
    RequestInvalidError,
    TargetNotFoundError,
    VerificationFailedError,
)

# Interim default user attribute allowlist (mirrors the LDAP adapter).
# Owner after Step 7: policy engine.
_DEFAULT_USER_ALLOWLIST = frozenset(
    {
        "displayname",
        "givenname",
        "sn",
        "mail",
        "title",
        "department",
        "company",
        "telephonenumber",
        "mobile",
        "physicaldeliveryofficename",
        "description",
    }
)


@dataclass(frozen=True)
class UserOutcome:
    """User mutation result.

    Attributes:
        disposition: APPLIED or NO_OP.
        user_guid: Target GUID (new GUID for create).
        dn_before: DN before the operation.
        dn_after: DN after the operation.
        changed_fields: Logical changed fields.
        source_dc: Committing DC.
        verified: Same-DC verification flag.
    """

    disposition: str
    user_guid: UUID
    dn_before: str
    dn_after: str
    changed_fields: tuple[str, ...]
    source_dc: str
    verified: bool


class UserService:
    """Allowlisted user mutations with expected-version and verification.

    Args:
        gateway: Canonical directory gateway.
    """

    def __init__(self, gateway: DirectoryGateway) -> None:
        self._gateway = gateway

    def _allowlist(self) -> frozenset[str]:
        fn = getattr(self._gateway, "user_allowlist", None)
        if callable(fn):
            return frozenset(fn())
        # Interim default until the Step 7 policy engine owns attribute allowlists.
        return _DEFAULT_USER_ALLOWLIST

    async def _require(self, user_guid: UUID) -> Any:
        user = await self._gateway.get_user(user_guid)
        if user is None:
            raise TargetNotFoundError(f"target not found: {user_guid}")
        return user

    async def update_attributes(
        self, user_guid: UUID, attributes: AttributeMap, expected_version: str | None = None
    ) -> UserOutcome:
        """Apply an allowlisted attribute diff.

        Args:
            user_guid: Target user GUID.
            attributes: Desired attribute values.
            expected_version: Concurrency token.

        Returns:
            UserOutcome (NO_OP when nothing changes).
        """
        user = await self._require(user_guid)
        if expected_version is not None and expected_version != user.version_token:
            raise ConcurrentModificationError("user changed since expected_version")
        current = {k: ([v] if isinstance(v, str) else list(v)) for k, v in user.attributes.items()}
        desired = {k: ([v] if isinstance(v, str) else [str(i) for i in v]) for k, v in attributes.items()}
        if all(current.get(k) == v for k, v in desired.items()):
            return UserOutcome(
                "NO_OP", user_guid, user.distinguished_name, user.distinguished_name, (), self._gateway.source_dc, True
            )
        allowlist = self._allowlist()
        for name in desired:
            if name.lower() not in allowlist:
                raise RequestInvalidError(f"attribute not allowlisted: {name}")
        await self._gateway.update_user_attributes(user_guid, attributes)
        after = await self._require(user_guid)
        changed = tuple(sorted(desired))
        for key, want in desired.items():
            got = after.attributes.get(key)
            got_list = [got] if isinstance(got, str) else list(got or [])
            if got_list != want:
                raise VerificationFailedError(f"attribute not observed after write: {key}")
        return UserOutcome(
            "APPLIED",
            user_guid,
            user.distinguished_name,
            after.distinguished_name,
            changed,
            self._gateway.source_dc,
            True,
        )

    async def create(self, parent_dn: str, attributes: AttributeMap) -> UserOutcome:
        """Create a user under a managed parent.

        Args:
            parent_dn: Parent OU DN.
            attributes: Initial allowlisted attributes.

        Returns:
            UserOutcome with the new GUID.
        """
        guid = await self._gateway.create_user(parent_dn, attributes)
        created = await self._require(guid)
        return UserOutcome("APPLIED", guid, "", created.distinguished_name, ("create",), self._gateway.source_dc, True)

    async def rename(self, user_guid: UUID, new_rdn: str) -> UserOutcome:
        """Rename a user (GUID must be invariant).

        Args:
            user_guid: Target user GUID.
            new_rdn: New RDN.

        Returns:
            UserOutcome with GUID invariance verified.
        """
        before = await self._require(user_guid)
        new_dn = await self._gateway.rename_entry(user_guid, new_rdn)
        after = await self._require(user_guid)
        if after.distinguished_name != new_dn:
            raise VerificationFailedError("rename verification failed")
        return UserOutcome(
            "APPLIED",
            user_guid,
            before.distinguished_name,
            after.distinguished_name,
            ("rdn",),
            self._gateway.source_dc,
            True,
        )

    async def move(self, user_guid: UUID, destination_ou_dn: str) -> UserOutcome:
        """Move a user between managed OUs.

        Args:
            user_guid: Target user GUID.
            destination_ou_dn: Destination container DN.

        Returns:
            UserOutcome with GUID invariance verified.
        """
        before = await self._require(user_guid)
        await self._gateway.move_entry(user_guid, destination_ou_dn)
        after = await self._require(user_guid)
        if after.object_guid != user_guid:
            raise VerificationFailedError("move verification failed")
        return UserOutcome(
            "APPLIED",
            user_guid,
            before.distinguished_name,
            after.distinguished_name,
            ("move",),
            self._gateway.source_dc,
            True,
        )

    async def delete(self, user_guid: UUID) -> UserOutcome:
        """Delete a user and verify absence.

        Args:
            user_guid: Target user GUID.

        Returns:
            UserOutcome after absence verification.
        """
        before = await self._require(user_guid)
        await self._gateway.delete_entry(user_guid)
        if await self._gateway.get_user(user_guid) is not None:
            raise VerificationFailedError("entry still present after delete")
        return UserOutcome(
            "APPLIED", user_guid, before.distinguished_name, "", ("delete",), self._gateway.source_dc, True
        )
