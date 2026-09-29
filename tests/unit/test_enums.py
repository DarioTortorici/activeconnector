"""Unit: domain enums match the operating plan (§6.1) when the domain track lands."""

import pytest

domain_enums = pytest.importorskip(
    "mwa_ad_connector.domain.enums",
    reason="Domain track (Step 2) has not landed yet.",
)

EXPECTED = {
    "ObjectType": {"USER", "GROUP", "OU"},
    "IdentifierType": {"OBJECT_GUID", "UPN", "SAM_ACCOUNT_NAME", "MAIL", "DISTINGUISHED_NAME", "GROUP_NAME"},
    "OperationState": {
        "RECEIVED",
        "AUTHORIZED",
        "EXECUTING",
        "AD_COMMITTED",
        "AD_VERIFIED",
        "WAITING_ENTRA_SYNC",
        "ENTRA_CONVERGED",
        "FAILED",
        "FAILED_VERIFICATION",
        "EXPIRED",
        "ESCALATED",
    },
    "RiskLevel": {"LOW", "MEDIUM", "HIGH", "CRITICAL"},
    "ApprovalMode": {"NONE", "REQUIRED", "TWO_PERSON", "BREAK_GLASS_FORBIDDEN"},
    "MutationDisposition": {"APPLIED", "NO_OP", "REJECTED", "QUEUED", "PARTIALLY_OBSERVED"},
    "HealthState": {"HEALTHY", "DEGRADED", "UNHEALTHY"},
    "ErrorCategory": {
        "VALIDATION",
        "AUTHENTICATION",
        "AUTHORIZATION",
        "POLICY",
        "NOT_FOUND",
        "AMBIGUOUS",
        "CONFLICT",
        "CONCURRENCY",
        "DEPENDENCY",
        "VERIFICATION",
        "TIMEOUT",
        "RATE_LIMIT",
        "INTERNAL",
    },
}


@pytest.mark.parametrize("enum_name,members", list(EXPECTED.items()))
def test_enum_members_match_plan(enum_name: str, members: set[str]) -> None:
    """Every plan enum exists with exactly the specified members (drift fails loudly)."""
    enum_cls = getattr(domain_enums, enum_name, None)
    if enum_cls is None:
        pytest.skip(f"Canonical enum {enum_name} absent: align tracks.")
    actual = {member.name for member in enum_cls}
    assert actual == members, f"{enum_name} drifted from the plan: {actual ^ members}"
