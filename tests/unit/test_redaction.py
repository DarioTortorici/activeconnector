"""Unit: redaction of secrets in logs/audit/evidence (local + canonical cross-check)."""

import pytest

from mwa_ad_connector.infrastructure.telemetry.logging import REDACTED_PLACEHOLDER, redact_mapping

_CANARY = "s3cret-canary"  # noqa: S105 - synthetic test canary, never a real credential.


def test_password_and_secret_keys_redacted() -> None:
    """Password/secret/token/nonce values are replaced at every level."""
    redacted = redact_mapping(
        {
            "new_password": _CANARY,
            "unicodePwd": _CANARY,
            "secret": "x",
            "token": "abc",
            "nonce": "n-1",
            "Authorization": "Bearer z",
            "sam_account_name": "jdoe",
        }
    )
    assert redacted["sam_account_name"] == "jdoe"
    for key in ("new_password", "unicodePwd", "secret", "token", "nonce", "Authorization"):
        assert redacted[key] == REDACTED_PLACEHOLDER


def test_redaction_is_recursive_and_preserves_shape() -> None:
    """Nested mappings/lists keep their shape with secrets redacted."""
    redacted = redact_mapping(
        {"parameters": {"new_password": _CANARY, "dry_run": False}, "items": [{"token": "t"}, {"name": "n"}]}
    )
    assert redacted["parameters"] == {"new_password": REDACTED_PLACEHOLDER, "dry_run": False}
    assert redacted["items"] == [{"token": REDACTED_PLACEHOLDER}, {"name": "n"}]


def test_canonical_redaction_agrees() -> None:
    """Canonical redact_dict (when landed) redacts the same secret set."""
    module = pytest.importorskip(
        "mwa_ad_connector.security.redaction", reason="Security track (Step 8) has not landed yet."
    )
    redact_dict = getattr(module, "redact_dict", None)
    assert callable(redact_dict), "Canonical redact_dict missing."
    redacted = redact_dict({"new_password": _CANARY, "sam_account_name": "jdoe"})
    assert redacted["sam_account_name"] == "jdoe"
    assert redacted["new_password"] != _CANARY, "Canonical redaction must hide passwords."
    assert REDACTED_PLACEHOLDER
