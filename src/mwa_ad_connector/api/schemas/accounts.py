"""Account action schemas: unlock, password, enable/disable (secret-safe)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from mwa_ad_connector.api.schemas.common import ApprovalContext


class UnlockAccountRequest(BaseModel):
    """Unlock a locked account (idempotent: already-unlocked is NO_OP)."""

    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=512)
    dry_run: bool = False


class ResetPasswordRequest(BaseModel):
    """Reset password over a protected channel (LDAPS enforced server-side).

    The secret is held in SecretStr, never logged, and excluded from audit/evidence.
    """

    model_config = ConfigDict(extra="forbid")

    new_password: SecretStr
    force_change_at_logon: bool = True
    reason: str | None = Field(default=None, max_length=512)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class ForcePasswordChangeRequest(BaseModel):
    """Force password change at next logon (pwdLastSet=0 semantics)."""

    model_config = ConfigDict(extra="forbid")

    force: bool = True
    reason: str | None = Field(default=None, max_length=512)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class EnableAccountRequest(BaseModel):
    """Enable a disabled account (bitwise-safe UAC update with verification)."""

    model_config = ConfigDict(extra="forbid")

    expected_version: str | None = Field(default=None, max_length=256)
    reason: str | None = Field(default=None, max_length=512)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class DisableAccountRequest(BaseModel):
    """Disable an account (reason mandatory; protected/service accounts rejected)."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=512)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False
