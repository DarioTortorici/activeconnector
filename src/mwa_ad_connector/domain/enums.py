"""Domain enumerations for the MWA AD connector.

Covers tables in Sections 6.1 of the operating plan. All enums are
``str``-based so they serialize deterministically to JSON/API contracts.
"""

from __future__ import annotations

from enum import StrEnum


class ObjectType(StrEnum):
    """AD object categories managed by the connector."""

    USER = "USER"
    GROUP = "GROUP"
    OU = "OU"


class IdentifierType(StrEnum):
    """Allowlisted identifier kinds for object resolution."""

    OBJECT_GUID = "OBJECT_GUID"
    UPN = "UPN"
    SAM_ACCOUNT_NAME = "SAM_ACCOUNT_NAME"
    MAIL = "MAIL"
    DISTINGUISHED_NAME = "DISTINGUISHED_NAME"
    GROUP_NAME = "GROUP_NAME"


class OperationState(StrEnum):
    """Lifecycle states for an operation (on-prem + cloud responsibilities)."""

    RECEIVED = "RECEIVED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    AD_COMMITTED = "AD_COMMITTED"
    AD_VERIFIED = "AD_VERIFIED"
    WAITING_ENTRA_SYNC = "WAITING_ENTRA_SYNC"
    ENTRA_CONVERGED = "ENTRA_CONVERGED"
    FAILED = "FAILED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    EXPIRED = "EXPIRED"
    ESCALATED = "ESCALATED"


class RiskLevel(StrEnum):
    """Risk classification driving approval and audit requirements."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalMode(StrEnum):
    """Approval strength required before executing a capability."""

    NONE = "NONE"
    REQUIRED = "REQUIRED"
    TWO_PERSON = "TWO_PERSON"
    BREAK_GLASS_FORBIDDEN = "BREAK_GLASS_FORBIDDEN"


class MutationDisposition(StrEnum):
    """Outcome of a mutation attempt from the caller's perspective."""

    APPLIED = "APPLIED"
    NO_OP = "NO_OP"
    REJECTED = "REJECTED"
    QUEUED = "QUEUED"
    PARTIALLY_OBSERVED = "PARTIALLY_OBSERVED"


class HealthState(StrEnum):
    """Aggregate or component health state."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


class ErrorCategory(StrEnum):
    """Stable error categories surfaced in ErrorResponse contracts."""

    VALIDATION = "VALIDATION"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    POLICY = "POLICY"
    NOT_FOUND = "NOT_FOUND"
    AMBIGUOUS = "AMBIGUOUS"
    CONFLICT = "CONFLICT"
    CONCURRENCY = "CONCURRENCY"
    DEPENDENCY = "DEPENDENCY"
    VERIFICATION = "VERIFICATION"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    INTERNAL = "INTERNAL"
