"""Policy package: capability catalog, scopes, protected targets, approvals, preflight."""

from mwa_ad_connector.policy.approvals import (
    ApprovalContext,
    ApprovalExpired,
    ApprovalRequired,
    ApprovalWrongCapability,
    WrongCapability,
    evaluate_approval,
)
from mwa_ad_connector.policy.catalog import (
    ALL_CAPABILITIES,
    CAPABILITY_CATALOG,
    ApprovalMode,
    CapabilityEntry,
    CapabilityNotAllowed,
    RiskLevel,
    get_entry,
    is_known,
    is_mutating,
    requires_approval,
)
from mwa_ad_connector.policy.engine import PolicyDecision, PolicyEngine
from mwa_ad_connector.policy.preflight import PreflightRequest, PreflightResult, preflight_request
from mwa_ad_connector.policy.protected_targets import (
    PRIVILEGED_GROUP_NAMES,
    PRIVILEGED_RIDS,
    PRIVILEGED_SID_SUFFIXES,
    check_target,
    is_protected_group,
    is_protected_user,
)
from mwa_ad_connector.policy.scopes import ScopeChecker, ScopeConfig, is_dn_inside, normalize_dn

__all__ = [
    "ALL_CAPABILITIES",
    "CAPABILITY_CATALOG",
    "PRIVILEGED_GROUP_NAMES",
    "PRIVILEGED_RIDS",
    "PRIVILEGED_SID_SUFFIXES",
    "ApprovalContext",
    "ApprovalExpired",
    "ApprovalMode",
    "ApprovalRequired",
    "ApprovalWrongCapability",
    "CapabilityEntry",
    "CapabilityNotAllowed",
    "PolicyDecision",
    "PolicyEngine",
    "PreflightRequest",
    "PreflightResult",
    "RiskLevel",
    "ScopeChecker",
    "ScopeConfig",
    "WrongCapability",
    "check_target",
    "evaluate_approval",
    "get_entry",
    "is_dn_inside",
    "is_known",
    "is_mutating",
    "is_protected_group",
    "is_protected_user",
    "normalize_dn",
    "preflight_request",
    "requires_approval",
]
