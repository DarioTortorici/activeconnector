"""Request preflight: catalog, scope, protected-target and approval checks (Step 7).

Preflight runs before any LDAP write and never touches the directory.
``dry_run`` requests go through the same checks; the flag is echoed back
so callers can distinguish validation-only evaluations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.policy.approvals import (
    ApprovalContext,
    ApprovalExpired,
    ApprovalRequired,
    WrongCapability,
    evaluate_approval,
)
from mwa_ad_connector.policy.catalog import CapabilityNotAllowed, get_entry
from mwa_ad_connector.policy.protected_targets import check_target
from mwa_ad_connector.policy.scopes import ScopeChecker


class PreflightRequest(BaseModel):
    """Input for a single preflight evaluation."""

    model_config = ConfigDict(extra="forbid")

    capability: str
    domain_id: str
    target_dn: str
    target_kind: Literal["user", "group", "ou"] = "user"
    target_attrs: dict[str, Any] = Field(default_factory=dict)
    approval: ApprovalContext | None = None
    dry_run: bool = False
    caller_scopes: list[str] | None = None


class PreflightResult(BaseModel):
    """Outcome of a preflight evaluation (explainable, auditable)."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    code: str
    reason: str
    capability: str
    dry_run: bool = False


def _deny(capability: str, code: str, reason: str, *, dry_run: bool = False) -> PreflightResult:
    return PreflightResult(allowed=False, code=code, reason=reason, capability=capability, dry_run=dry_run)


def preflight_request(
    request: PreflightRequest,
    *,
    scope_checker: ScopeChecker | None = None,
    now: datetime | None = None,
) -> PreflightResult:
    """Evaluate a capability request without touching the directory.

    Check order: catalog allowlist, DN scope, caller scopes, protected
    targets, approval context. The first failure wins so the reason is
    always explainable.
    """
    try:
        entry = get_entry(request.capability)
    except CapabilityNotAllowed as exc:
        return _deny(request.capability, exc.code, str(exc), dry_run=request.dry_run)

    if scope_checker is not None:
        scope_reason = scope_checker.check(request.domain_id, request.target_dn)
        if scope_reason is not None:
            return _deny(request.capability, "TARGET_OUT_OF_SCOPE", scope_reason, dry_run=request.dry_run)

    if request.caller_scopes is not None:
        missing = [scope for scope in entry.scopes if scope not in request.caller_scopes]
        if missing:
            return _deny(
                request.capability,
                "CAPABILITY_NOT_ALLOWED",
                f"caller lacks required scope(s): {', '.join(missing)}",
                dry_run=request.dry_run,
            )

    protected_reason = check_target(request.target_kind, {"dn": request.target_dn, **request.target_attrs})
    if protected_reason is not None:
        return _deny(request.capability, "PROTECTED_TARGET", protected_reason, dry_run=request.dry_run)

    try:
        evaluate_approval(
            entry.approval_mode,
            request.approval,
            capability=request.capability,
            now=now or datetime.now(UTC),
        )
    except (ApprovalRequired, ApprovalExpired, WrongCapability) as exc:
        code = getattr(exc, "code", "APPROVAL_REQUIRED")
        return _deny(request.capability, code, str(exc), dry_run=request.dry_run)

    reason = "preflight passed"
    if request.dry_run:
        reason = "preflight passed (dry-run: no directory write attempted)"
    return PreflightResult(
        allowed=True, code="OK", reason=reason, capability=request.capability, dry_run=request.dry_run
    )
