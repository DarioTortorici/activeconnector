"""Central domain-to-HTTP error mapping.

Stable taxonomy from the operating plan (section 8.7). Raw LDAP text must never
cross this boundary: only structured codes, categories and redacted details are
returned to callers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

try:  # Canonical domain taxonomy (Step 2); parallel track may land it later.
    from mwa_ad_connector.domain.errors import DomainError as _CanonicalDomainError
except ImportError:  # pragma: no cover - fallback until the domain track lands.
    _CanonicalDomainError = None  # type: ignore[assignment, misc]

_HTTP_CLIENT_ERROR_MIN = 400
_HTTP_SERVER_ERROR_MIN = 500


class ConnectorError(Exception):
    """Local domain fault used until/without the canonical DomainError.

    Mirrors the canonical shape (code/category/http/retryable/remediation) so
    handlers work identically for both exception types via duck-typing.
    """

    def __init__(  # noqa: PLR0913 - structured fault carries the full taxonomy row.
        self,
        code: str,
        message: str = "",
        *,
        category: str = "INTERNAL",
        http_status: int = 500,
        retryable: bool = False,
        remediation: str | None = None,
        details: dict[str, str] | None = None,
        dependency_code: str | None = None,
        operation_id: str | None = None,
    ) -> None:
        """Create a structured domain fault.

        Args:
            code: Stable domain code (e.g. TARGET_NOT_FOUND).
            message: Human-readable, redacted message (never raw LDAP text).
            category: Stable error category from the taxonomy.
            http_status: HTTP status to return.
            retryable: Whether the caller may retry with backoff.
            remediation: Operator-facing remediation hint.
            details: Redacted string-only detail map.
            dependency_code: Normalized downstream code (e.g. LDAP result code).
            operation_id: Related operation id, if any.
        """
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.category = category
        self.http_status = http_status
        self.retryable = retryable
        self.remediation = remediation
        self.details = details or {}
        self.dependency_code = dependency_code
        self.operation_id = operation_id


# code -> (category, http_status, retryable). Source: operating plan section 8.7.
CODE_TABLE: dict[str, tuple[str, int, bool]] = {
    "REQUEST_INVALID": ("VALIDATION", 400, False),
    "PAYLOAD_TOO_LARGE": ("VALIDATION", 413, False),
    "AUTHENTICATION_FAILED": ("AUTHENTICATION", 401, False),
    "CALLER_FORBIDDEN": ("AUTHORIZATION", 403, False),
    "TENANT_BINDING_MISMATCH": ("AUTHORIZATION", 403, False),
    "REPLAY_DETECTED": ("AUTHENTICATION", 409, False),
    "CAPABILITY_NOT_ALLOWED": ("POLICY", 403, False),
    "TARGET_OUT_OF_SCOPE": ("POLICY", 403, False),
    "PROTECTED_TARGET": ("POLICY", 403, False),
    "APPROVAL_REQUIRED": ("POLICY", 409, False),
    "TARGET_NOT_FOUND": ("NOT_FOUND", 404, False),
    "AMBIGUOUS_TARGET": ("AMBIGUOUS", 409, False),
    "IDEMPOTENCY_COLLISION": ("CONFLICT", 409, False),
    "CONCURRENT_MODIFICATION": ("CONCURRENCY", 409, False),
    "LDAP_CONSTRAINT_VIOLATION": ("CONFLICT", 409, False),
    "LDAP_INSUFFICIENT_ACCESS": ("AUTHORIZATION", 403, False),
    "LDAP_UNAVAILABLE": ("DEPENDENCY", 503, True),
    "LDAP_TIMEOUT": ("TIMEOUT", 504, True),
    "LDAPS_CERTIFICATE_INVALID": ("DEPENDENCY", 503, False),
    "AD_COMMITTED_VERIFICATION_FAILED": ("VERIFICATION", 502, False),
    "RATE_LIMITED": ("RATE_LIMIT", 429, True),
    "INTERNAL_ERROR": ("INTERNAL", 500, False),
}

# Remediation hints per code (operator-facing, static text).
REMEDIATION_TABLE: dict[str, str] = {
    "REQUEST_INVALID": "Fix the request payload/headers and retry.",
    "AUTHENTICATION_FAILED": "Present a valid, unexpired caller token and retry.",
    "CALLER_FORBIDDEN": "Request the missing scope/role; do not retry unchanged.",
    "TENANT_BINDING_MISMATCH": "Align X-Tenant-ID, token tenant and envelope tenant.",
    "REPLAY_DETECTED": "Generate a fresh nonce/timestamp; never resend the same envelope.",
    "CAPABILITY_NOT_ALLOWED": "Use an allowlisted capability or request policy approval.",
    "TARGET_OUT_OF_SCOPE": "Target an object inside the managed Base DN/OU scope.",
    "PROTECTED_TARGET": "Target is privileged/protected; request an approved exception workflow.",
    "APPROVAL_REQUIRED": "Attach a valid approval context and retry.",
    "TARGET_NOT_FOUND": "Verify the object GUID and domain, then retry.",
    "AMBIGUOUS_TARGET": "Disambiguate with object_guid and retry.",
    "IDEMPOTENCY_COLLISION": "Reuse the original payload for this key or use a new key.",
    "CONCURRENT_MODIFICATION": "Refresh expected_version and retry.",
    "LDAP_CONSTRAINT_VIOLATION": "Fix the conflicting value/policy and retry.",
    "LDAP_INSUFFICIENT_ACCESS": "Grant the documented minimum AD delegation to the service identity.",
    "LDAP_UNAVAILABLE": "Retry with backoff; escalate if the DC stays unreachable.",
    "LDAP_TIMEOUT": "Retry with backoff; check DC responsiveness.",
    "LDAPS_CERTIFICATE_INVALID": "Renew/fix the LDAPS trust chain; never downgrade to cleartext.",
    "AD_COMMITTED_VERIFICATION_FAILED": "Manual review required: commit accepted but verification failed.",
    "RATE_LIMITED": "Back off and retry after the indicated delay.",
    "INTERNAL_ERROR": "Contact operations with operation_id and correlation_id.",
}


def fault_fields(exc: BaseException) -> dict[str, Any]:
    """Extract structured fault fields from canonical or local domain errors.

    Args:
        exc: Raised exception (canonical DomainError, ConnectorError, or other).

    Returns:
        Dict with code/category/message/http_status/retryable/remediation/details.
    """
    code = getattr(exc, "code", None) or "INTERNAL_ERROR"
    if not isinstance(code, str) or code not in CODE_TABLE:
        code = "INTERNAL_ERROR"
    category, http_status, retryable = CODE_TABLE[code]
    message = str(getattr(exc, "message", None) or getattr(exc, "args", [""])[0] or code)
    remediation = getattr(exc, "remediation", None) or REMEDIATION_TABLE.get(code)
    raw_details = getattr(exc, "details", None) or {}
    details = {str(k): str(v) for k, v in raw_details.items()} if isinstance(raw_details, dict) else {}
    return {
        "code": code,
        "category": getattr(exc, "category", None) or category,
        "message": message[:1000],
        "http_status": int(getattr(exc, "http_status", None) or http_status),
        "retryable": bool(getattr(exc, "retryable", None) or retryable),
        "remediation": remediation,
        "details": details,
        "dependency_code": getattr(exc, "dependency_code", None),
        "operation_id": getattr(exc, "operation_id", None),
    }


def error_body(fields: dict[str, Any], correlation_id: str | None) -> dict[str, Any]:
    """Build the stable JSON error envelope.

    Args:
        fields: Output of fault_fields().
        correlation_id: Request correlation id for supportability.

    Returns:
        JSON-serializable error envelope (redacted by construction).
    """
    return {
        "error": {
            "code": fields["code"],
            "category": fields["category"],
            "message": fields["message"],
            "retryable": fields["retryable"],
            "operation_id": fields.get("operation_id"),
            "correlation_id": correlation_id,
            "details": fields.get("details", {}),
            "remediation": fields.get("remediation"),
            "dependency_code": fields.get("dependency_code"),
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }


def _correlation_id(request: Request) -> str | None:
    """Best-effort correlation id for error bodies."""
    state_id = getattr(request.state, "correlation_id", None)
    if isinstance(state_id, str) and state_id:
        return state_id
    header_id = request.headers.get("X-Correlation-ID")
    return header_id if header_id else None


def _bump_api_error(request: Request, code: str) -> None:
    """Increment the api error counter when metrics are attached to app.state."""
    try:
        metrics = getattr(request.app.state, "metrics", None)
        if metrics is not None:
            metrics.inc_api_error(code=code)
    except Exception:  # noqa: BLE001, S110 - metrics must never break error handling.
        pass


async def domain_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Map canonical/local domain faults to stable HTTP error bodies."""
    fields = fault_fields(exc)
    _bump_api_error(request, fields["code"])
    return JSONResponse(status_code=fields["http_status"], content=error_body(fields, _correlation_id(request)))


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Map Pydantic/FastAPI validation failures to 400 REQUEST_INVALID.

    Field names are reported; submitted values are never echoed (leakage guard).
    """
    locations = sorted({str((err.get("loc") or ("?",))[-1]) for err in exc.errors()})
    fields = {
        "code": "REQUEST_INVALID",
        "category": "VALIDATION",
        "message": f"Request validation failed for: {', '.join(locations) or 'body'}.",
        "http_status": 400,
        "retryable": False,
        "remediation": REMEDIATION_TABLE["REQUEST_INVALID"],
        "details": {"fields": ",".join(locations[:10])},
        "dependency_code": None,
        "operation_id": None,
    }
    _bump_api_error(request, "REQUEST_INVALID")
    return JSONResponse(status_code=400, content=error_body(fields, _correlation_id(request)))


async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Map bare HTTP exceptions to the stable envelope (status preserved)."""
    status = exc.status_code
    code = {401: "AUTHENTICATION_FAILED", 403: "CALLER_FORBIDDEN", 404: "TARGET_NOT_FOUND"}.get(status)
    if code is None:
        code = "REQUEST_INVALID" if _HTTP_CLIENT_ERROR_MIN <= status < _HTTP_SERVER_ERROR_MIN else "INTERNAL_ERROR"
    category, _, retryable = CODE_TABLE[code]
    fields = {
        "code": code,
        "category": category,
        "message": str(exc.detail)[:1000] if isinstance(exc.detail, str) else code,
        "http_status": status,
        "retryable": retryable,
        "remediation": REMEDIATION_TABLE.get(code),
        "details": {},
        "dependency_code": None,
        "operation_id": None,
    }
    _bump_api_error(request, code)
    return JSONResponse(status_code=status, content=error_body(fields, _correlation_id(request)))


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort 500 mapping: no internal text leaks to the caller."""
    fields = {
        "code": "INTERNAL_ERROR",
        "category": "INTERNAL",
        "message": "Internal connector error.",
        "http_status": 500,
        "retryable": False,
        "remediation": REMEDIATION_TABLE["INTERNAL_ERROR"],
        "details": {},
        "dependency_code": None,
        "operation_id": None,
    }
    _bump_api_error(request, "INTERNAL_ERROR")
    return JSONResponse(status_code=500, content=error_body(fields, _correlation_id(request)))


def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers on the application.

    Args:
        app: FastAPI application to configure.
    """
    app.add_exception_handler(ConnectorError, domain_error_handler)
    canonical: Any = _CanonicalDomainError
    if canonical is not None and canonical is not ConnectorError:
        app.add_exception_handler(canonical, domain_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_error_handler)
