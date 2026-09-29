"""Unit: stable error taxonomy (§8.7) in the API mapping plus canonical cross-check."""

import json

import pytest
from fastapi.exceptions import RequestValidationError

from mwa_ad_connector.api import error_handlers
from mwa_ad_connector.api.error_handlers import ConnectorError, domain_error_handler, fault_fields

EXPECTED_HTTP = {
    "REQUEST_INVALID": 400,
    "PAYLOAD_TOO_LARGE": 413,
    "AUTHENTICATION_FAILED": 401,
    "CALLER_FORBIDDEN": 403,
    "TENANT_BINDING_MISMATCH": 403,
    "REPLAY_DETECTED": 409,
    "CAPABILITY_NOT_ALLOWED": 403,
    "TARGET_OUT_OF_SCOPE": 403,
    "PROTECTED_TARGET": 403,
    "APPROVAL_REQUIRED": 409,
    "TARGET_NOT_FOUND": 404,
    "AMBIGUOUS_TARGET": 409,
    "IDEMPOTENCY_COLLISION": 409,
    "CONCURRENT_MODIFICATION": 409,
    "LDAP_CONSTRAINT_VIOLATION": 409,
    "LDAP_INSUFFICIENT_ACCESS": 403,
    "LDAP_UNAVAILABLE": 503,
    "LDAP_TIMEOUT": 504,
    "LDAPS_CERTIFICATE_INVALID": 503,
    "AD_COMMITTED_VERIFICATION_FAILED": 502,
    "RATE_LIMITED": 429,
    "INTERNAL_ERROR": 500,
}


@pytest.mark.parametrize("code,http_status", list(EXPECTED_HTTP.items()))
def test_code_table_http_mapping(code: str, http_status: int) -> None:
    """Every taxonomy code maps to its specified HTTP status and retry flag."""
    assert code in error_handlers.CODE_TABLE, f"Missing taxonomy code: {code}"
    _, mapped_http, retryable = error_handlers.CODE_TABLE[code]
    assert mapped_http == http_status
    assert isinstance(retryable, bool)


def test_failed_verification_is_502_manual() -> None:
    """FAILED_VERIFICATION is 502/non-auto-retryable (never a plain pre-commit error)."""
    category, http_status, retryable = error_handlers.CODE_TABLE["AD_COMMITTED_VERIFICATION_FAILED"]
    assert (category, http_status, retryable) == ("VERIFICATION", 502, False)


def test_unknown_exception_becomes_internal_error() -> None:
    """Unshaped exceptions collapse to INTERNAL_ERROR (no leakage, no contract)."""
    fields = fault_fields(RuntimeError("dc=example (1) result=49"))
    assert fields["code"] == "INTERNAL_ERROR"
    assert fields["http_status"] == 500


def test_fault_fields_keep_structured_shape() -> None:
    """ConnectorError fields survive mapping with redacted string-only details."""
    exc = ConnectorError(
        code="TARGET_NOT_FOUND",
        message="gone",
        category="NOT_FOUND",
        http_status=404,
        operation_id="op-1",
        details={"guid": "abc"},
    )
    fields = fault_fields(exc)
    assert fields["code"] == "TARGET_NOT_FOUND"
    assert fields["operation_id"] == "op-1"
    assert fields["details"] == {"guid": "abc"}


async def test_validation_handler_hides_submitted_values() -> None:
    """422 bodies name fields but never echo secrets/values (leakage guard)."""
    exc = RequestValidationError(
        [
            {
                "type": "missing",
                "loc": ("body", "new_password"),
                "msg": "Field required",
                "input": {"x": "s3cret-value"},
            }
        ]
    )

    class _State:
        correlation_id = "corr-1"

    class _App:
        state = type("S", (), {"metrics": None})()

    class _Request:
        state = _State()
        headers: dict[str, str] = {}
        app = _App()

    response = await error_handlers.validation_error_handler(_Request(), exc)  # type: ignore[arg-type]
    assert response.status_code == 400
    body = json.loads(bytes(response.body).decode())
    assert body["error"]["code"] == "REQUEST_INVALID"
    assert "s3cret-value" not in json.dumps(body)
    assert "new_password" in json.dumps(body)


def test_canonical_domain_error_uses_same_mapping() -> None:
    """Canonical DomainError subclasses map through the same taxonomy."""
    canonical = pytest.importorskip(
        "mwa_ad_connector.domain.errors", reason="Domain track (Step 2) has not landed yet."
    )
    cases = [
        ("RequestInvalidError", 400),
        ("TargetNotFoundError", 404),
        ("AmbiguousTargetError", 409),
        ("ProtectedTargetError", 403),
        ("ApprovalRequiredError", 409),
        ("IdempotencyCollisionError", 409),
        ("VerificationFailedError", 502),
        ("DependencyUnavailableError", 503),
    ]
    for class_name, http_status in cases:
        cls = getattr(canonical, class_name, None)
        if cls is None:
            pytest.skip(f"Canonical error {class_name} absent: align tracks.")
        assert fault_fields(cls("gone"))["http_status"] == http_status
    assert domain_error_handler is not None
