"""Domain error taxonomy (operating plan Section 8.7).

Maps stable domain error codes to category, HTTP status and retry
semantics. Free-form LDAP diagnostic text must never become an API
contract; only these codes are surfaced to callers.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict


class ErrorCode(StrEnum):
    """Stable domain error codes returned in ErrorResponse envelopes."""

    REQUEST_INVALID = "REQUEST_INVALID"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    CALLER_FORBIDDEN = "CALLER_FORBIDDEN"
    TENANT_BINDING_MISMATCH = "TENANT_BINDING_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    CAPABILITY_NOT_ALLOWED = "CAPABILITY_NOT_ALLOWED"
    TARGET_OUT_OF_SCOPE = "TARGET_OUT_OF_SCOPE"
    PROTECTED_TARGET = "PROTECTED_TARGET"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    AMBIGUOUS_TARGET = "AMBIGUOUS_TARGET"
    IDEMPOTENCY_COLLISION = "IDEMPOTENCY_COLLISION"
    CONCURRENT_MODIFICATION = "CONCURRENT_MODIFICATION"
    LDAP_CONSTRAINT_VIOLATION = "LDAP_CONSTRAINT_VIOLATION"
    LDAP_INSUFFICIENT_ACCESS = "LDAP_INSUFFICIENT_ACCESS"
    LDAP_UNAVAILABLE = "LDAP_UNAVAILABLE"
    LDAP_TIMEOUT = "LDAP_TIMEOUT"
    LDAPS_CERTIFICATE_INVALID = "LDAPS_CERTIFICATE_INVALID"
    AD_COMMITTED_VERIFICATION_FAILED = "AD_COMMITTED_VERIFICATION_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ErrorMetadata(BaseModel):
    """Static metadata for a single error code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ErrorCode
    category: str
    http_status: int
    retryable: bool
    retry_note: str = ""


_ERROR_TABLE: Final[tuple[ErrorMetadata, ...]] = (
    ErrorMetadata(code=ErrorCode.REQUEST_INVALID, category="VALIDATION", http_status=400, retryable=False),
    ErrorMetadata(code=ErrorCode.PAYLOAD_TOO_LARGE, category="VALIDATION", http_status=413, retryable=False),
    ErrorMetadata(code=ErrorCode.AUTHENTICATION_FAILED, category="AUTHENTICATION", http_status=401, retryable=False),
    ErrorMetadata(code=ErrorCode.CALLER_FORBIDDEN, category="AUTHORIZATION", http_status=403, retryable=False),
    ErrorMetadata(code=ErrorCode.TENANT_BINDING_MISMATCH, category="AUTHORIZATION", http_status=403, retryable=False),
    ErrorMetadata(code=ErrorCode.REPLAY_DETECTED, category="AUTHENTICATION", http_status=409, retryable=False),
    ErrorMetadata(code=ErrorCode.CAPABILITY_NOT_ALLOWED, category="POLICY", http_status=403, retryable=False),
    ErrorMetadata(code=ErrorCode.TARGET_OUT_OF_SCOPE, category="POLICY", http_status=403, retryable=False),
    ErrorMetadata(code=ErrorCode.PROTECTED_TARGET, category="POLICY", http_status=403, retryable=False),
    ErrorMetadata(code=ErrorCode.APPROVAL_REQUIRED, category="POLICY", http_status=409, retryable=False),
    ErrorMetadata(code=ErrorCode.TARGET_NOT_FOUND, category="NOT_FOUND", http_status=404, retryable=False),
    ErrorMetadata(code=ErrorCode.AMBIGUOUS_TARGET, category="AMBIGUOUS", http_status=409, retryable=False),
    ErrorMetadata(code=ErrorCode.IDEMPOTENCY_COLLISION, category="CONFLICT", http_status=409, retryable=False),
    ErrorMetadata(
        code=ErrorCode.CONCURRENT_MODIFICATION,
        category="CONCURRENCY",
        http_status=409,
        retryable=False,
        retry_note="Retry only with a fresh expected_version after re-read.",
    ),
    ErrorMetadata(code=ErrorCode.LDAP_CONSTRAINT_VIOLATION, category="CONFLICT", http_status=409, retryable=False),
    ErrorMetadata(code=ErrorCode.LDAP_INSUFFICIENT_ACCESS, category="AUTHORIZATION", http_status=403, retryable=False),
    ErrorMetadata(code=ErrorCode.LDAP_UNAVAILABLE, category="DEPENDENCY", http_status=503, retryable=True),
    ErrorMetadata(code=ErrorCode.LDAP_TIMEOUT, category="TIMEOUT", http_status=504, retryable=True),
    ErrorMetadata(code=ErrorCode.LDAPS_CERTIFICATE_INVALID, category="DEPENDENCY", http_status=503, retryable=False),
    ErrorMetadata(
        code=ErrorCode.AD_COMMITTED_VERIFICATION_FAILED,
        category="VERIFICATION",
        http_status=502,
        retryable=False,
        retry_note="Manual triage required; commit may have succeeded.",
    ),
    ErrorMetadata(code=ErrorCode.RATE_LIMITED, category="RATE_LIMIT", http_status=429, retryable=True),
    ErrorMetadata(code=ErrorCode.INTERNAL_ERROR, category="INTERNAL", http_status=500, retryable=False),
)

ERROR_METADATA: Final[dict[ErrorCode, ErrorMetadata]] = {m.code: m for m in _ERROR_TABLE}


def http_status_for(code: ErrorCode) -> int:
    """Return the HTTP status mapped to an error code.

    Args:
        code: Stable domain error code.

    Returns:
        HTTP status integer from Section 8.7.
    """
    return ERROR_METADATA[code].http_status


def is_retryable(code: ErrorCode) -> bool:
    """Return whether an error code permits automatic retry.

    Args:
        code: Stable domain error code.

    Returns:
        True when retry with backoff is allowed.
    """
    return ERROR_METADATA[code].retryable


class DomainError(Exception):
    """Base class for all domain errors.

    Attributes:
        code: Stable error code surfaced to callers.
        message: Redacted, user-safe message (no LDAP free text).
        details: Optional redacted details mapping.
    """

    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        """Initialize a domain error.

        Args:
            message: Redacted human-readable message.
            details: Optional redacted key/value details.
        """
        super().__init__(message)
        self.message = message
        self.details: dict[str, str] = dict(details) if details else {}

    @property
    def http_status(self) -> int:
        """HTTP status mapped from the error code."""
        return http_status_for(self.code)

    @property
    def retryable(self) -> bool:
        """Whether the error permits automatic retry."""
        return is_retryable(self.code)


class RequestInvalidError(DomainError):
    """Request failed structural or semantic validation."""

    code: ErrorCode = ErrorCode.REQUEST_INVALID


class TargetNotFoundError(DomainError):
    """Target object could not be resolved to exactly one entry."""

    code: ErrorCode = ErrorCode.TARGET_NOT_FOUND


class AmbiguousTargetError(DomainError):
    """Resolution matched more than one entry; refusing heuristics."""

    code: ErrorCode = ErrorCode.AMBIGUOUS_TARGET


class PolicyDeniedError(DomainError):
    """Policy engine denied the capability, scope or target."""

    code: ErrorCode = ErrorCode.CAPABILITY_NOT_ALLOWED


class ProtectedTargetError(DomainError):
    """Target is privileged/protected and blocked by policy."""

    code: ErrorCode = ErrorCode.PROTECTED_TARGET


class ApprovalRequiredError(DomainError):
    """Operation requires an approval context that is missing or invalid."""

    code: ErrorCode = ErrorCode.APPROVAL_REQUIRED


class IdempotencyCollisionError(DomainError):
    """Same idempotency key reused with a different canonical payload."""

    code: ErrorCode = ErrorCode.IDEMPOTENCY_COLLISION


class ConcurrentModificationError(DomainError):
    """Expected version mismatch; caller must re-read and retry."""

    code: ErrorCode = ErrorCode.CONCURRENT_MODIFICATION


class VerificationFailedError(DomainError):
    """LDAP commit accepted but read-after-write verification failed."""

    code: ErrorCode = ErrorCode.AD_COMMITTED_VERIFICATION_FAILED


class DependencyUnavailableError(DomainError):
    """LDAP/DC dependency unavailable or timed out."""

    code: ErrorCode = ErrorCode.LDAP_UNAVAILABLE
