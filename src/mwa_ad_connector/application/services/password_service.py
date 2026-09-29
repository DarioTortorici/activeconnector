"""Password service (secret-safe reset + force-change)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from pydantic import SecretStr

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.domain.errors import DomainError, ErrorCode, ProtectedTargetError, TargetNotFoundError

logger = logging.getLogger(__name__)


class InsecureChannelError(DomainError):
    """Password write refused: transport is not LDAPS."""

    code = ErrorCode.LDAPS_CERTIFICATE_INVALID


@dataclass(frozen=True)
class PasswordOutcome:
    """Password mutation result (never carries the secret).

    Attributes:
        user_guid: Target user GUID.
        changed_fields: Logical changed fields.
        source_dc: Committing DC.
        verified: Indirect verification flag.
    """

    user_guid: UUID
    changed_fields: tuple[str, ...]
    source_dc: str
    verified: bool


class PasswordService:
    """Reset passwords and toggle force-change without logging secrets.

    Args:
        gateway: Canonical directory gateway.
        is_protected: Optional protected-target check.
    """

    def __init__(
        self,
        gateway: DirectoryGateway,
        is_protected: Callable[[UUID], tuple[bool, list[str]]] | None = None,
    ) -> None:
        self._gateway = gateway
        self._is_protected = is_protected or (lambda _g: (False, []))

    async def reset(self, user_guid: UUID, password: SecretStr) -> PasswordOutcome:
        """Reset a password over LDAPS only.

        Args:
            user_guid: Target user GUID.
            password: New password (never logged, audited or retained).

        Returns:
            PasswordOutcome with indirect verification.

        Raises:
            InsecureChannelError: If the transport is not LDAPS.
        """
        protected, reasons = self._is_protected(user_guid)
        if protected:
            raise ProtectedTargetError(f"protected account: {'; '.join(reasons) or 'policy'}")
        if not bool(getattr(self._gateway, "is_secure_transport", True)):
            raise InsecureChannelError("password reset requires LDAPS")
        before = await self._gateway.get_user(user_guid)
        if before is None:
            raise TargetNotFoundError(f"target not found: {user_guid}")
        await self._gateway.reset_password(user_guid, password.get_secret_value())
        logger.info("password reset committed", extra={"user_guid": str(user_guid)})
        after = await self._gateway.get_user(user_guid)
        if after is None:
            from mwa_ad_connector.domain.errors import VerificationFailedError  # noqa: PLC0415

            raise VerificationFailedError("post-reset read inconclusive")
        return PasswordOutcome(user_guid, ("unicodePwd",), self._gateway.source_dc, verified=True)

    async def force_change(self, user_guid: UUID, force: bool) -> PasswordOutcome:
        """Set/clear the must-change-password flag via pwdLastSet.

        Args:
            user_guid: Target user GUID.
            force: True writes pwdLastSet=0 (must change at next logon).

        Returns:
            PasswordOutcome verified on the same DC.
        """
        if await self._gateway.get_user(user_guid) is None:
            raise TargetNotFoundError(f"target not found: {user_guid}")
        await self._gateway.set_pwd_last_set(user_guid, 0 if force else -1)
        return PasswordOutcome(user_guid, ("pwdLastSet",), self._gateway.source_dc, verified=True)
