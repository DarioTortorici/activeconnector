"""Operations package: lifecycle state machine, idempotency, audit, retention."""

from mwa_ad_connector.operations.audit import AuditEntry, AuditService, AuditSink, AuditStage
from mwa_ad_connector.operations.idempotency import (
    IdempotencyClaim,
    IdempotencyCollision,
    OperationRepository,
    canonical_request_hash,
    check,
    reserve,
)
from mwa_ad_connector.operations.retention import (
    RetentionResult,
    SupportsPurge,
    apply_retention,
    default_terminal_states,
)
from mwa_ad_connector.operations.state_machine import (
    ON_PREM_TERMINAL_STATES,
    TERMINAL_STATES,
    TRANSITIONS,
    InvalidTransition,
    OperationState,
    advance,
    can_transition,
    is_terminal,
)

__all__ = [
    "ON_PREM_TERMINAL_STATES",
    "TERMINAL_STATES",
    "TRANSITIONS",
    "AuditEntry",
    "AuditService",
    "AuditSink",
    "AuditStage",
    "IdempotencyClaim",
    "IdempotencyCollision",
    "InvalidTransition",
    "OperationRepository",
    "OperationState",
    "RetentionResult",
    "SupportsPurge",
    "advance",
    "apply_retention",
    "can_transition",
    "canonical_request_hash",
    "check",
    "default_terminal_states",
    "is_terminal",
    "reserve",
]
