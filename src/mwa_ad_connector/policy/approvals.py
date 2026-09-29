"""Approval evaluation: NONE / REQUIRED / TWO_PERSON / BREAK_GLASS_FORBIDDEN (Step 7)."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.policy.catalog import ApprovalMode

_FUTURE_TOLERANCE_SECONDS = 300
_TWO_PERSON_QUORUM = 2


class ApprovalRequired(Exception):
    """Raised when a required approval is missing, weak or forbidden."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "APPROVAL_REQUIRED"


class ApprovalExpired(Exception):
    """Raised when the approval context is past its validity window."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "APPROVAL_REQUIRED"


class WrongCapability(Exception):
    """Raised when the approval was issued for a different capability."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "APPROVAL_REQUIRED"


# Clearer alias kept in sync with the plan's short error name.
ApprovalWrongCapability = WrongCapability


class ApprovalContext(BaseModel):
    """Approval evidence attached to a capability request."""

    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1)
    approved_by: list[str] = Field(min_length=1)
    approved_at: datetime
    expires_at: datetime | None = None
    capability: str | None = None


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def evaluate_approval(
    mode: ApprovalMode,
    approval: ApprovalContext | None,
    *,
    capability: str,
    now: datetime,
    max_age_seconds: int = 3600,
) -> ApprovalContext | None:
    """Validate ``approval`` against the catalog ``mode`` for ``capability``.

    Args:
        mode: Approval mode from the capability catalog entry.
        approval: Approval context supplied with the request, if any.
        capability: Capability being authorized (must match the approval).
        now: Reference time for freshness checks.
        max_age_seconds: Maximum age of ``approved_at`` when the approval
            carries no explicit ``expires_at``.

    Returns:
        The validated approval, or None when ``mode`` is ``NONE``.

    Raises:
        ApprovalRequired: Missing/weak approval, or any approval attempt
            under ``BREAK_GLASS_FORBIDDEN`` (fail-closed).
        ApprovalExpired: Approval past ``expires_at`` or ``max_age_seconds``.
        WrongCapability: Approval issued for another capability.
    """
    current = _ensure_aware(now)
    if mode is ApprovalMode.NONE:
        return None
    if mode is ApprovalMode.BREAK_GLASS_FORBIDDEN:
        raise ApprovalRequired(f"capability {capability!r} forbids break-glass execution")
    if approval is None:
        raise ApprovalRequired(f"capability {capability!r} requires an approval context")
    if approval.capability is not None and approval.capability != capability:
        raise WrongCapability(
            f"approval {approval.approval_id!r} was issued for {approval.capability!r}, not for {capability!r}"
        )
    if not approval.approved_by or any(not name.strip() for name in approval.approved_by):
        raise ApprovalRequired("approval must list at least one non-empty approver identity")
    approved_at = _ensure_aware(approval.approved_at)
    if (approved_at - current).total_seconds() > _FUTURE_TOLERANCE_SECONDS:
        raise ApprovalRequired("approval timestamp is in the future")
    if approval.expires_at is not None:
        if current > _ensure_aware(approval.expires_at):
            raise ApprovalExpired(f"approval {approval.approval_id!r} is past expires_at")
    elif (current - approved_at).total_seconds() > max_age_seconds:
        raise ApprovalExpired(f"approval {approval.approval_id!r} is older than {max_age_seconds}s")
    if mode is ApprovalMode.TWO_PERSON and len({name.strip() for name in approval.approved_by}) < _TWO_PERSON_QUORUM:
        raise ApprovalRequired(f"capability {capability!r} requires two distinct approvers")
    return approval
