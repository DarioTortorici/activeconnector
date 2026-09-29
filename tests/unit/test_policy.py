"""Unit: policy allowlists deny by default (schema-level guards + canonical engine)."""

import pytest

from mwa_ad_connector.api.schemas.groups import GROUP_WRITABLE_ATTRIBUTES
from mwa_ad_connector.api.schemas.users import USER_WRITABLE_ATTRIBUTES

FORBIDDEN_EVERYWHERE = {
    "unicodePwd",
    "unicodepwd",
    "password",
    "userPassword",
    "nTSecurityDescriptor",
    "member;range",
    "objectSid",
    "objectGUID",
    "whenChanged",
    "uSNChanged",
}


def test_user_allowlist_excludes_secrets_and_system_attrs() -> None:
    """User attribute allowlist holds only delegated, non-secret attributes."""
    assert USER_WRITABLE_ATTRIBUTES, "Allowlist must not be empty."
    assert not (
        FORBIDDEN_EVERYWHERE & {a.lower() for a in USER_WRITABLE_ATTRIBUTES}
        | FORBIDDEN_EVERYWHERE & USER_WRITABLE_ATTRIBUTES
    )


def test_group_allowlist_excludes_membership_and_secrets() -> None:
    """Group allowlist excludes member linkage, secrets and system attributes."""
    assert GROUP_WRITABLE_ATTRIBUTES, "Allowlist must not be empty."
    assert "member" not in GROUP_WRITABLE_ATTRIBUTES
    assert not (FORBIDDEN_EVERYWHERE & GROUP_WRITABLE_ATTRIBUTES)


def test_canonical_policy_engine_deny_by_default() -> None:
    """Canonical policy engine (when landed) exposes deny-by-default evaluation."""
    engine = pytest.importorskip("mwa_ad_connector.policy.engine", reason="Policy track (Step 7) has not landed yet.")
    engine_cls = getattr(engine, "PolicyEngine", None)
    assert engine_cls is not None, "Canonical PolicyEngine class missing."
    assert callable(getattr(engine_cls, "evaluate", None)), "PolicyEngine.evaluate missing."
    assert callable(getattr(engine_cls, "decide", None)), "PolicyEngine.decide missing."
    assert getattr(engine, "PolicyDecision", None) is not None, "PolicyDecision model missing."
