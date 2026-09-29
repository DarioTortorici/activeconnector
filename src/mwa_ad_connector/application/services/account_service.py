"""Account state service (unlock / enable / disable with protection)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.domain.errors import (
    ConcurrentModificationError,
    ProtectedTargetError,
    TargetNotFoundError,
    VerificationFailedError,
)


@dataclass(frozen=True)
class AccountOutcome:
    """Account mutation result.

    Attributes:
        disposition: APPLIED or NO_OP.
        user_guid: Target user GUID.
        changed_fields: Logical changed fields.
        source_dc: Committing DC.
        verified: Same-DC verification flag.
    """

    disposition: str
    user_guid: UUID
    changed_fields: tuple[str, ...]
    source_dc: str
    verified: bool


class AccountService:
    """Unlock/enable/disable accounts with protected-target checks.

    Args:
        gateway: Canonical directory gateway.
        is_protected: Callable returning (protected, reasons) for a user GUID.
    """

    def __init__(
        self,
        gateway: DirectoryGateway,
        is_protected: Callable[[UUID], tuple[bool, list[str]]] | None = None,
    ) -> None:
        self._gateway = gateway
        self._is_protected = is_protected or (lambda _g: (False, []))

    def _guard(self, user_guid: UUID) -> None:
        protected, reasons = self._is_protected(user_guid)
        if protected:
            raise ProtectedTargetError(f"protected account: {'; '.join(reasons) or 'policy'}")

    async def unlock(self, user_guid: UUID) -> AccountOutcome:
        """Unlock an account (idempotent when already unlocked).

        Args:
            user_guid: Target user GUID.

        Returns:
            AccountOutcome verified on the same DC.
        """
        self._guard(user_guid)
        user = await self._gateway.get_user(user_guid)
        if user is None:
            raise TargetNotFoundError(f"target not found: {user_guid}")
        if not user.locked:
            return AccountOutcome("NO_OP", user_guid, (), self._gateway.source_dc, verified=True)
        await self._gateway.unlock_account(user_guid)
        after = await self._gateway.get_user(user_guid)
        if after is None or after.locked:
            raise VerificationFailedError("account still locked after unlock")
        return AccountOutcome("APPLIED", user_guid, ("lockoutTime",), self._gateway.source_dc, verified=True)

    async def set_enabled(self, user_guid: UUID, enable: bool, expected_version: str | None = None) -> AccountOutcome:
        """Enable/disable an account.

        Args:
            user_guid: Target user GUID.
            enable: True to enable, False to disable.
            expected_version: Concurrency token checked against the user view.

        Returns:
            AccountOutcome verified on the same DC.
        """
        self._guard(user_guid)
        user = await self._gateway.get_user(user_guid)
        if user is None:
            raise TargetNotFoundError(f"target not found: {user_guid}")
        if expected_version is not None and expected_version != user.version_token:
            raise ConcurrentModificationError("user changed since expected_version")
        if user.enabled == enable:
            return AccountOutcome("NO_OP", user_guid, (), self._gateway.source_dc, verified=True)
        await self._gateway.set_account_enabled(user_guid, enable)
        after = await self._gateway.get_user(user_guid)
        if after is None or after.enabled != enable:
            raise VerificationFailedError("enabled state not observed after write")
        return AccountOutcome("APPLIED", user_guid, ("userAccountControl",), self._gateway.source_dc, verified=True)
