"""Runtime error mapping: policy denials and infrastructure faults to domain errors."""

from __future__ import annotations

from mwa_ad_connector.domain.errors import (
    ApprovalRequiredError,
    DomainError,
    ErrorCode,
    PolicyDeniedError,
    ProtectedTargetError,
    RequestInvalidError,
)

_KNOWN_CODES: frozenset[str] = frozenset(member.value for member in ErrorCode)


class OutOfScopeError(DomainError):
    """Target DN falls outside the configured managed scope."""

    code = ErrorCode.TARGET_OUT_OF_SCOPE


_POLICY_ERRORS: dict[str, type[DomainError]] = {
    "TARGET_OUT_OF_SCOPE": OutOfScopeError,
    "PROTECTED_TARGET": ProtectedTargetError,
    "APPROVAL_REQUIRED": ApprovalRequiredError,
}


class MappedDomainError(DomainError):
    """Domain error carrying an explicit stable error code."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        """Initialize the mapped error.

        Args:
            code: Stable domain error code.
            message: Redacted, caller-safe message.
        """
        super().__init__(message)
        self.code = code


def deny_to_error(code: str, reason: str) -> DomainError:
    """Convert a preflight denial code to the matching domain error.

    Args:
        code: Preflight denial code (e.g. TARGET_OUT_OF_SCOPE).
        reason: Explainable deny reason (redacted by construction).

    Returns:
        Domain error carrying the stable code mapped by api/error_handlers.
    """
    error_type = _POLICY_ERRORS.get(code)
    message = reason or code
    if error_type is not None:
        return error_type(message)
    return PolicyDeniedError(message)


def coerce_infrastructure_fault(exc: Exception) -> DomainError:
    """Convert LDAP/adapter runtime faults into mapped domain errors.

    Adapter faults carry ``CODE: remediation`` text where CODE is a stable
    domain code; unknown faults become INTERNAL_ERROR without leaking text.

    Args:
        exc: Exception raised by the gateway or an application service.

    Returns:
        Domain error safe for the API error handlers.
    """
    if isinstance(exc, DomainError):
        return exc
    head, _, rest = str(exc).partition(":")
    candidate = head.strip()
    if candidate in _KNOWN_CODES:
        return MappedDomainError(ErrorCode(candidate), rest.strip() or candidate)
    if isinstance(exc, (ValueError, LookupError)):
        return RequestInvalidError(str(exc) or "request invalid")
    return MappedDomainError(ErrorCode.INTERNAL_ERROR, "internal connector error")
