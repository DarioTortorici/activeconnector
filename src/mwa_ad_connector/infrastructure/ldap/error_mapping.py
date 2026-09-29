"""Map LDAP result codes (plus AD subcodes) to domain errors.

Only numeric result codes and structured subcodes drive the contract;
free-form diagnostic text is never returned to callers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SUBCODE_RE = re.compile(r"data\s+([0-9a-fA-F]{3,4})")

# result code -> (ErrorCode, Category, HTTP, retryable)
_RESULT_MAP: dict[int, tuple[str, str, int, bool]] = {
    0: ("OK", "INTERNAL", 200, False),
    1: ("LDAP_OPERATIONS_ERROR", "DEPENDENCY", 503, True),
    2: ("LDAP_PROTOCOL_ERROR", "VALIDATION", 400, False),
    3: ("LDAP_TIME_LIMIT", "TIMEOUT", 504, True),
    4: ("LDAP_SIZE_LIMIT", "VALIDATION", 400, False),
    7: ("LDAP_AUTH_METHOD_NOT_SUPPORTED", "AUTHENTICATION", 401, False),
    8: ("LDAP_STRONG_AUTH_REQUIRED", "AUTHENTICATION", 401, False),
    16: ("LDAP_NO_SUCH_ATTRIBUTE", "VALIDATION", 400, False),
    17: ("LDAP_UNDEFINED_TYPE", "VALIDATION", 400, False),
    18: ("LDAP_INAPPROPRIATE_MATCHING", "VALIDATION", 400, False),
    19: ("LDAP_CONSTRAINT_VIOLATION", "CONFLICT", 409, False),
    20: ("LDAP_TYPE_OR_VALUE_EXISTS", "CONFLICT", 409, False),
    21: ("LDAP_INVALID_SYNTAX", "VALIDATION", 400, False),
    32: ("TARGET_NOT_FOUND", "NOT_FOUND", 404, False),
    33: ("LDAP_ALIAS_PROBLEM", "NOT_FOUND", 404, False),
    34: ("LDAP_INVALID_DN", "VALIDATION", 400, False),
    48: ("LDAP_INAPPROPRIATE_AUTH", "AUTHENTICATION", 401, False),
    49: ("LDAP_INVALID_CREDENTIALS", "AUTHENTICATION", 401, False),
    50: ("LDAP_INSUFFICIENT_ACCESS", "AUTHORIZATION", 403, False),
    51: ("LDAP_BUSY", "DEPENDENCY", 503, True),
    52: ("LDAP_UNAVAILABLE", "DEPENDENCY", 503, True),
    53: ("LDAP_UNWILLING_TO_PERFORM", "DEPENDENCY", 503, False),
    64: ("LDAP_NAMING_VIOLATION", "VALIDATION", 400, False),
    65: ("LDAP_OBJECT_CLASS_VIOLATION", "VALIDATION", 400, False),
    66: ("LDAP_NOT_ALLOWED_ON_NONLEAF", "CONFLICT", 409, False),
    67: ("LDAP_NOT_ALLOWED_ON_RDN", "CONFLICT", 409, False),
    68: ("LDAP_ALREADY_EXISTS", "CONFLICT", 409, False),
    69: ("LDAP_NO_OBJECT_CLASS_MODS", "VALIDATION", 400, False),
    71: ("LDAP_AFFECTS_MULTIPLE_DSAS", "VALIDATION", 400, False),
    80: ("LDAP_OTHER", "INTERNAL", 500, False),
    81: ("LDAP_TIMEOUT", "TIMEOUT", 504, True),
    82: ("LDAP_CONNECT_ERROR", "DEPENDENCY", 503, True),
}

# AD data subcode (for result 49) -> (ErrorCode, remediation hint)
_AD_SUBCODES: dict[str, tuple[str, str]] = {
    "525": ("TARGET_NOT_FOUND", "Verify the bind identity exists."),
    "52e": ("AUTHENTICATION_FAILED", "Verify service account credentials."),
    "530": ("CALLER_FORBIDDEN", "Logon not permitted at this time."),
    "531": ("CALLER_FORBIDDEN", "Logon not permitted from this workstation."),
    "532": ("AUTHENTICATION_FAILED", "Service account password expired; rotate it."),
    "533": ("CALLER_FORBIDDEN", "Service account is disabled."),
    "701": ("AUTHENTICATION_FAILED", "Service account expired."),
    "773": ("AUTHENTICATION_FAILED", "Service account must reset password."),
    "775": ("AUTHENTICATION_FAILED", "Service account is locked out."),
}


@dataclass(frozen=True)
class LdapMappedError:
    """Normalized LDAP failure.

    Attributes:
        code: Stable domain error code.
        category: Error category.
        http_status: Mapped HTTP status.
        retryable: Whether retry may help.
        remediation: Safe remediation hint (no raw diagnostics).
        result_code: Numeric LDAP result code.
        subcode: AD data subcode when present.
    """

    code: str
    category: str
    http_status: int
    retryable: bool
    remediation: str
    result_code: int
    subcode: str | None = None


def extract_ad_subcode(diagnostic: str | None) -> str | None:
    """Extract the AD data subcode from a diagnostic string.

    Args:
        diagnostic: Raw server diagnostic (never returned to callers).

    Returns:
        Lower-cased subcode or None.
    """
    if not diagnostic:
        return None
    match = _SUBCODE_RE.search(diagnostic)
    return match.group(1).lower() if match else None


def map_ldap_result(result_code: int, diagnostic: str | None = None, operation: str = "") -> LdapMappedError:
    """Map a numeric LDAP result (plus AD subcode) to a domain error.

    Args:
        result_code: Numeric LDAP result code.
        diagnostic: Raw diagnostic text (used only for subcode parsing).
        operation: Operation name for remediation context.

    Returns:
        Normalized :class:`LdapMappedError` without raw text.
    """
    subcode = extract_ad_subcode(diagnostic)
    if result_code == 49 and subcode in _AD_SUBCODES:  # noqa: PLR2004
        code, remediation = _AD_SUBCODES[subcode]
        category = "NOT_FOUND" if code == "TARGET_NOT_FOUND" else "AUTHENTICATION"
        http_status = 404 if code == "TARGET_NOT_FOUND" else 401
        return LdapMappedError(code, category, http_status, False, remediation, result_code, subcode)
    mapped = _RESULT_MAP.get(result_code)
    if mapped is None:
        return LdapMappedError(
            "INTERNAL_ERROR", "INTERNAL", 500, False, f"LDAP operation failed ({operation}).", result_code
        )
    code, category, http_status, retryable = mapped
    remediation = f"LDAP {operation or 'operation'} returned code {result_code}."
    if code == "LDAP_INVALID_CREDENTIALS":
        remediation = "Verify service account credentials and LDAPS trust."
    elif code == "LDAP_INSUFFICIENT_ACCESS":
        remediation = "Grant the delegated ACL for this operation; avoid privileged accounts."
    elif code in ("LDAP_UNAVAILABLE", "LDAP_BUSY", "LDAP_CONNECT_ERROR", "LDAP_TIMEOUT"):
        remediation = "DC unavailable or busy; retry with backoff on the pinned DC."
    return LdapMappedError(code, category, http_status, retryable, remediation, result_code, subcode)
