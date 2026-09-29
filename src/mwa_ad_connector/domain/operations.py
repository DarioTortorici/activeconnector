"""Operation contracts (Sections 6.5-6.7, 6.9).

Covers command envelope fields, caller identity, mutation results and
durable operation records with state-machine invariants.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mwa_ad_connector.domain.capabilities import is_known_capability, is_mutation_capability
from mwa_ad_connector.domain.enums import MutationDisposition, OperationState, RiskLevel
from mwa_ad_connector.domain.evidence import EntraEvidenceHint, VerificationEvidence
from mwa_ad_connector.domain.identifiers import ObjectReference

TERMINAL_STATES: Final[frozenset[OperationState]] = frozenset(
    {
        OperationState.ENTRA_CONVERGED,
        OperationState.FAILED,
        OperationState.FAILED_VERIFICATION,
        OperationState.EXPIRED,
        OperationState.ESCALATED,
    }
)

ALLOWED_TRANSITIONS: Final[dict[OperationState, frozenset[OperationState]]] = {
    OperationState.RECEIVED: frozenset({OperationState.AUTHORIZED, OperationState.FAILED, OperationState.EXPIRED}),
    OperationState.AUTHORIZED: frozenset({OperationState.EXECUTING, OperationState.FAILED, OperationState.EXPIRED}),
    OperationState.EXECUTING: frozenset({OperationState.AD_COMMITTED, OperationState.FAILED, OperationState.EXPIRED}),
    OperationState.AD_COMMITTED: frozenset(
        {OperationState.AD_VERIFIED, OperationState.FAILED_VERIFICATION, OperationState.FAILED}
    ),
    OperationState.AD_VERIFIED: frozenset({OperationState.WAITING_ENTRA_SYNC, OperationState.ESCALATED}),
    OperationState.WAITING_ENTRA_SYNC: frozenset(
        {OperationState.ENTRA_CONVERGED, OperationState.FAILED, OperationState.EXPIRED, OperationState.ESCALATED}
    ),
    OperationState.ENTRA_CONVERGED: frozenset(),
    OperationState.FAILED: frozenset(),
    OperationState.FAILED_VERIFICATION: frozenset({OperationState.ESCALATED}),
    OperationState.EXPIRED: frozenset(),
    OperationState.ESCALATED: frozenset(),
}


def is_terminal(state: OperationState) -> bool:
    """Check whether an operation state is terminal.

    Args:
        state: Candidate state.

    Returns:
        True for terminal states.
    """
    return state in TERMINAL_STATES


def is_legal_transition(from_state: OperationState, to_state: OperationState) -> bool:
    """Check whether a state transition is legal.

    Args:
        from_state: Current state.
        to_state: Desired next state.

    Returns:
        True when the transition is allowed.
    """
    return to_state in ALLOWED_TRANSITIONS.get(from_state, frozenset())


class ApprovalContext(BaseModel):
    """Approval evidence attached to risky capability requests.

    Attributes:
        approval_id: Approval ticket/record identifier.
        approved_by: Identities that approved the request.
        approved_at: Approval timestamp (timezone-aware).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(min_length=1, max_length=128)
    approved_by: list[str] = Field(min_length=1)
    approved_at: datetime


class CapabilityRequest(BaseModel):
    """Validated command envelope for one capability invocation.

    Attributes:
        api_version: Envelope major version marker.
        capability: Allowlisted capability identifier.
        customer_id: Customer boundary.
        tenant_id: Tenant boundary.
        connector_id: Target connector binding.
        forest_id: Forest boundary.
        domain_id: Domain boundary.
        target: Object reference (GUID required for mutations).
        parameters: Capability-specific parameters (no extras at schema layer).
        dry_run: When True, run preflight only without mutations.
        idempotency_key: Deduplication key (required for mutations).
        correlation_id: Correlation identifier for tracing.
        ticket_id: Ticket binding (required for mutations).
        requested_at: Request timestamp (timezone-aware).
        expires_at: Request deadline (must exceed requested_at).
        nonce: Single-use anti-replay value.
        approval_context: Approval evidence for risky capabilities.
        expected_version: Optimistic concurrency token when relevant.
        requested_by: Requesting identity label.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    api_version: str = Field(default="1.0", min_length=1, max_length=16)
    capability: str = Field(min_length=1, max_length=64)
    customer_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    connector_id: str = Field(min_length=1, max_length=128)
    forest_id: str = Field(min_length=1, max_length=128)
    domain_id: str = Field(min_length=1, max_length=128)
    target: ObjectReference
    parameters: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    ticket_id: str | None = Field(default=None, min_length=1, max_length=128)
    requested_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=8, max_length=128)
    approval_context: ApprovalContext | None = None
    expected_version: str | None = Field(default=None, min_length=1, max_length=256)
    requested_by: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def _check_envelope_invariants(self) -> Self:
        """Enforce catalog membership, deadlines and mutation bindings.

        Returns:
            The validated request.

        Raises:
            ValueError: On unknown capability, inverted deadlines, missing
                mutation bindings, or GUID-less mutation targets.
        """
        if not is_known_capability(self.capability):
            raise ValueError(f"Unknown capability: {self.capability}")
        if self.expires_at <= self.requested_at:
            raise ValueError("expires_at must be after requested_at")
        if is_mutation_capability(self.capability) and not self.dry_run:
            if self.idempotency_key is None:
                raise ValueError("idempotency_key is required for mutations")
            if self.ticket_id is None:
                raise ValueError("ticket_id is required for mutations")
            if not self.target.has_stable_identity:
                raise ValueError("Mutations require target object_guid")
        return self


class CallerContext(BaseModel):
    """Already-authenticated caller identity for authorization and audit.

    Attributes:
        subject: Authenticated subject identifier.
        issuer: Token/certificate issuer.
        audience: Token audience.
        tenant_id: Tenant bound to the credential.
        customer_id: Customer bound to the credential.
        connector_id: Connector bound to the credential.
        scopes: Granted scopes.
        roles: Granted roles.
        certificate_thumbprint: mTLS thumbprint when applicable.
        auth_method: Authentication mechanism label.
        token_id: Token identifier for replay/audit linkage.
        authenticated_at: Authentication timestamp (timezone-aware).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str = Field(min_length=1, max_length=256)
    issuer: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    customer_id: str = Field(min_length=1, max_length=128)
    connector_id: str = Field(min_length=1, max_length=128)
    scopes: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    certificate_thumbprint: str | None = Field(default=None, min_length=1, max_length=128)
    auth_method: str = Field(min_length=1, max_length=64)
    token_id: str = Field(min_length=1, max_length=128)
    authenticated_at: datetime


class MutationResult(BaseModel):
    """Redacted outcome of a verified mutation.

    Attributes:
        operation_id: Operation identifier.
        state: Final or intermediate operation state.
        disposition: Caller-visible outcome classification.
        target_object_guid: Mutated object identity.
        resolved_dn_before: DN observed before commit.
        resolved_dn_after: DN observed after commit/verify.
        changed_fields: Redacted list of changed field names.
        verification_evidence: Read-after-write proof when available.
        source_dc: Pinned DC for commit and verification.
        committed_at: Commit timestamp when known.
        verified_at: Verification timestamp when known.
        warnings: Non-fatal warning labels.
        rollback_status: Compensation outcome label when attempted.
        entra_evidence_hint: Correlation hints for the cloud poller.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(min_length=1, max_length=128)
    state: OperationState
    disposition: MutationDisposition
    target_object_guid: UUID
    resolved_dn_before: str | None = Field(default=None, max_length=512)
    resolved_dn_after: str | None = Field(default=None, max_length=512)
    changed_fields: list[str] = Field(default_factory=list)
    verification_evidence: VerificationEvidence | None = None
    source_dc: str = Field(min_length=1, max_length=256)
    committed_at: datetime | None = None
    verified_at: datetime | None = None
    warnings: list[str] = Field(default_factory=list)
    rollback_status: str | None = Field(default=None, max_length=128)
    entra_evidence_hint: EntraEvidenceHint | None = None


class StateTransition(BaseModel):
    """Single durable state transition in an operation history.

    Attributes:
        from_state: Previous state (None for the initial transition).
        to_state: New state.
        at: Transition timestamp (timezone-aware).
        reason: Redacted reason label.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    from_state: OperationState | None = None
    to_state: OperationState
    at: datetime
    reason: str = Field(default="", max_length=512)


class OperationRecord(BaseModel):
    """Durable operation record with idempotency and audit linkage.

    Attributes:
        operation_id: Operation identifier.
        customer_id: Customer boundary.
        tenant_id: Tenant boundary.
        connector_id: Connector boundary.
        forest_id: Forest boundary.
        domain_id: Domain boundary.
        capability: Executed capability.
        risk: Capability risk at execution time.
        request_hash: Canonical request hash for collision detection.
        idempotency_key: Deduplication key unique per tenant+connector.
        correlation_id: Correlation identifier.
        ticket_id: Ticket binding when present.
        caller_subject: Redacted caller identity label.
        target_guid: Resolved target GUID when known.
        state: Current state.
        history: Ordered transition history.
        selected_dc: Pinned DC for the operation.
        created_at: Creation timestamp.
        updated_at: Last update timestamp.
        deadline: Operation deadline.
        error_code: Terminal error code when failed.
        verification_evidence: Verification proof when available.
        audit_chain_reference: Audit chain linkage token.
        retry_count: Number of transport-level retries.
        transport_message_id: Inbound message identifier when present.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(min_length=1, max_length=128)
    customer_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    connector_id: str = Field(min_length=1, max_length=128)
    forest_id: str = Field(min_length=1, max_length=128)
    domain_id: str = Field(min_length=1, max_length=128)
    capability: str = Field(min_length=1, max_length=64)
    risk: RiskLevel
    request_hash: str = Field(min_length=1, max_length=256)
    idempotency_key: str = Field(min_length=8, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    ticket_id: str | None = Field(default=None, max_length=128)
    caller_subject: str = Field(min_length=1, max_length=256)
    target_guid: UUID | None = None
    state: OperationState
    history: list[StateTransition] = Field(default_factory=list)
    selected_dc: str | None = Field(default=None, max_length=256)
    created_at: datetime
    updated_at: datetime
    deadline: datetime
    error_code: str | None = Field(default=None, max_length=64)
    verification_evidence: VerificationEvidence | None = None
    audit_chain_reference: str | None = Field(default=None, max_length=256)
    retry_count: int = Field(default=0, ge=0)
    transport_message_id: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def _check_record_invariants(self) -> Self:
        """Validate transition legality and deadline ordering.

        Returns:
            The validated record.

        Raises:
            ValueError: On illegal transitions, terminal-state regression,
                deadline inversion, or unknown capability.
        """
        if not is_known_capability(self.capability):
            raise ValueError(f"Unknown capability: {self.capability}")
        if self.deadline < self.created_at:
            raise ValueError("deadline must not precede created_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        previous: OperationState | None = None
        for transition in self.history:
            if transition.from_state != previous:
                raise ValueError("history chain is discontinuous")
            if previous is not None and is_terminal(previous):
                raise ValueError("record must not regress from a terminal state")
            if previous is not None and not is_legal_transition(previous, transition.to_state):
                raise ValueError(f"Illegal transition {previous} -> {transition.to_state}")
            previous = transition.to_state
        if self.history and self.history[-1].to_state != self.state:
            raise ValueError("state must match the last history transition")
        return self


__all__ = [
    "ALLOWED_TRANSITIONS",
    "TERMINAL_STATES",
    "ApprovalContext",
    "CallerContext",
    "CapabilityRequest",
    "MutationResult",
    "OperationRecord",
    "StateTransition",
    "is_legal_transition",
    "is_terminal",
]
