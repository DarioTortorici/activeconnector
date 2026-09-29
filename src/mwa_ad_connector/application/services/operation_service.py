"""Operation orchestrator (RECEIVED→AUTHORIZED→EXECUTING→COMMITTED→VERIFIED).

Coordinates the canonical :class:`OperationRepository`, :class:`AuditSink`,
policy engine and capability callbacks. Returns domain ``MutationResult``
values; the Entra hint never claims convergence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from mwa_ad_connector.application.ports.audit_sink import AuditSink
from mwa_ad_connector.application.ports.operation_repository import OperationRepository
from mwa_ad_connector.domain.capabilities import get_metadata
from mwa_ad_connector.domain.enums import MutationDisposition, OperationState
from mwa_ad_connector.domain.errors import (
    ConcurrentModificationError,
    IdempotencyCollisionError,
    PolicyDeniedError,
)
from mwa_ad_connector.domain.evidence import EntraEvidenceHint, VerificationEvidence
from mwa_ad_connector.domain.operations import (
    CallerContext,
    CapabilityRequest,
    MutationResult,
    OperationRecord,
    StateTransition,
)


@dataclass(frozen=True)
class MutationParts:
    """Callback-provided mutation facts for the orchestrator record.

    Attributes:
        target_guid: Mutated object GUID.
        dn_before: DN observed before commit.
        dn_after: DN observed after commit.
        changed_fields: Redacted changed field names.
        target_upn: UPN hint for the cloud poller when known.
    """

    target_guid: UUID
    dn_before: str | None = None
    dn_after: str | None = None
    changed_fields: list[str] | None = None
    target_upn: str | None = None


MutateFn = Callable[[], Awaitable[MutationParts]]
VerifyFn = Callable[[], Awaitable[VerificationEvidence | None]]


class PolicyEngine(Protocol):
    """Minimal policy surface required by the orchestrator."""

    async def authorize(self, request: CapabilityRequest, caller: CallerContext) -> bool:
        """Return True when the request is allowed by policy.

        Args:
            request: Validated capability request.
            caller: Authenticated caller context.

        Returns:
            Policy decision.
        """
        ...


def _utcnow() -> datetime:
    return datetime.now(UTC)


def canonical_request_hash(request: CapabilityRequest) -> str:
    """Hash the canonical request body for idempotency collision detection.

    Args:
        request: Validated capability request.

    Returns:
        Hex digest over capability, target, parameters and scope binding.
    """
    body = {
        "capability": request.capability,
        "target": request.target.model_dump(mode="json"),
        "parameters": request.parameters,
        "tenant_id": request.tenant_id,
        "connector_id": request.connector_id,
        "domain_id": request.domain_id,
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


class OperationService:
    """Coordinate store + audit + idempotency + policy + execution.

    Capability handlers supply ``mutate``/``verify`` callbacks so this file
    stays small and capability-agnostic.

    Args:
        store: Canonical operation repository.
        audit: Canonical audit sink.
        policy: Optional policy engine exposing ``authorize``.
        source_dc: Pinned DC label recorded on new records.
    """

    def __init__(
        self, store: OperationRepository, audit: AuditSink, policy: PolicyEngine | None = None, source_dc: str = ""
    ) -> None:
        self._store = store
        self._audit = audit
        self._policy = policy
        self._source_dc = source_dc

    async def execute(  # noqa: PLR0913
        self,
        request: CapabilityRequest,
        caller: CallerContext,
        mutate: MutateFn,
        verify: VerifyFn | None = None,
    ) -> MutationResult:
        """Run the full state machine for one capability request.

        Args:
            request: Validated capability request.
            caller: Authenticated caller context.
            mutate: Callback performing the AD mutation.
            verify: Optional callback performing read-after-write.

        Returns:
            Final domain ``MutationResult``.
        """
        digest = canonical_request_hash(request)
        key = request.idempotency_key or f"dry-{request.nonce}"
        replay = await self._replay_if_terminal(request, digest, key)
        if replay is not None:
            return replay
        record = await self._create_record(request, caller, digest, key)
        await self._audit_event(record, caller, "RECEIVED", {})
        await self._move(record.operation_id, OperationState.AUTHORIZED, "authorized")
        await self._audit_event(record, caller, "AUTHORIZED", {})
        if self._policy is not None:
            allowed = await self._policy.authorize(request, caller)
            if not allowed:
                await self._move(record.operation_id, OperationState.FAILED, "policy denied")
                raise PolicyDeniedError("capability denied by policy")
        if request.dry_run:
            target = request.target.object_guid or UUID(int=0)
            return MutationResult(
                operation_id=record.operation_id,
                state=OperationState.AUTHORIZED,
                disposition=MutationDisposition.NO_OP,
                target_object_guid=target,
                source_dc=self._source_dc,
                entra_evidence_hint=self._entra_hint(None, None),
            )
        await self._move(record.operation_id, OperationState.EXECUTING, "executing")
        try:
            parts = await mutate()
        except Exception as exc:
            await self._audit_event(record, caller, "FAILED", {"error": type(exc).__name__})
            await self._move(record.operation_id, OperationState.FAILED, "mutation failed")
            raise
        await self._move(record.operation_id, OperationState.AD_COMMITTED, "committed")
        evidence: VerificationEvidence | None = None
        if verify is not None:
            try:
                evidence = await verify()
            except Exception as exc:
                await self._audit_event(record, caller, "FAILED_VERIFICATION", {"error": type(exc).__name__})
                await self._move(record.operation_id, OperationState.FAILED_VERIFICATION, "verify error")
                return self._result(record, parts, OperationState.FAILED_VERIFICATION, None)
        matched = True if evidence is None else evidence.matched
        if not matched:
            await self._audit_event(record, caller, "FAILED_VERIFICATION", {})
            await self._move(record.operation_id, OperationState.FAILED_VERIFICATION, "verify mismatch")
            return self._result(record, parts, OperationState.FAILED_VERIFICATION, evidence)
        await self._audit_event(record, caller, "AD_VERIFIED", {})
        await self._move(record.operation_id, OperationState.AD_VERIFIED, "verified")
        final = await self._store.get(record.operation_id)
        stored_evidence = final.verification_evidence if final else evidence
        _ = stored_evidence
        return self._result(record, parts, OperationState.AD_VERIFIED, evidence)

    async def _replay_if_terminal(self, request: CapabilityRequest, digest: str, key: str) -> MutationResult | None:
        existing = await self._store.get_by_idempotency_key(request.tenant_id, request.connector_id, key)
        if existing is None:
            return None
        if existing.request_hash != digest:
            raise IdempotencyCollisionError("idempotency key reused with a different payload")
        if existing.state not in (
            OperationState.AD_VERIFIED,
            OperationState.FAILED,
            OperationState.FAILED_VERIFICATION,
            OperationState.AUTHORIZED,
        ):
            raise ConcurrentModificationError("operation with this key is already in progress")
        disposition = (
            MutationDisposition.APPLIED
            if existing.state == OperationState.AD_VERIFIED
            else (
                MutationDisposition.NO_OP
                if existing.state == OperationState.AUTHORIZED
                else MutationDisposition.REJECTED
            )
        )
        return MutationResult(
            operation_id=existing.operation_id,
            state=existing.state,
            disposition=disposition,
            target_object_guid=existing.target_guid or UUID(int=0),
            source_dc=existing.selected_dc or "",
            verification_evidence=existing.verification_evidence,
            entra_evidence_hint=self._entra_hint(None, None),
        )

    async def _create_record(
        self, request: CapabilityRequest, caller: CallerContext, digest: str, key: str
    ) -> OperationRecord:
        now = _utcnow()
        try:
            risk = get_metadata(request.capability).risk
        except KeyError:
            from mwa_ad_connector.domain.enums import RiskLevel  # noqa: PLC0415

            risk = RiskLevel.MEDIUM
        record = OperationRecord(
            operation_id=f"op-{uuid4().hex[:12]}",
            customer_id=request.customer_id,
            tenant_id=request.tenant_id,
            connector_id=request.connector_id,
            forest_id=request.forest_id,
            domain_id=request.domain_id,
            capability=request.capability,
            risk=risk,
            request_hash=digest,
            idempotency_key=key,
            correlation_id=request.correlation_id,
            ticket_id=request.ticket_id,
            caller_subject=caller.subject,
            target_guid=request.target.object_guid,
            state=OperationState.RECEIVED,
            history=[StateTransition(from_state=None, to_state=OperationState.RECEIVED, at=now, reason="received")],
            selected_dc=self._source_dc or None,
            created_at=now,
            updated_at=now,
            deadline=request.expires_at,
        )
        await self._store.save(record)
        return record

    async def _move(self, operation_id: str, to_state: OperationState, reason: str) -> None:
        await self._store.transition(operation_id, to_state, reason)

    async def _audit_event(
        self, record: OperationRecord, caller: CallerContext, outcome: str, details: dict[str, str]
    ) -> None:
        await self._audit.append(
            operation_id=record.operation_id,
            capability=record.capability,
            tenant_id=record.tenant_id,
            connector_id=record.connector_id,
            caller_subject=caller.subject,
            target_guid=record.target_guid,
            outcome=outcome,
            redacted_details=details,
            occurred_at=_utcnow(),
        )

    def _result(
        self,
        record: OperationRecord,
        parts: MutationParts,
        state: OperationState,
        evidence: VerificationEvidence | None,
    ) -> MutationResult:
        return MutationResult(
            operation_id=record.operation_id,
            state=state,
            disposition=MutationDisposition.APPLIED,
            target_object_guid=parts.target_guid,
            resolved_dn_before=parts.dn_before,
            resolved_dn_after=parts.dn_after,
            changed_fields=list(parts.changed_fields or []),
            verification_evidence=evidence,
            source_dc=self._source_dc,
            committed_at=_utcnow(),
            verified_at=_utcnow() if evidence else None,
            entra_evidence_hint=self._entra_hint(parts.target_upn, parts),
        )

    @staticmethod
    def _entra_hint(target_upn: str | None, parts: MutationParts | None) -> EntraEvidenceHint:
        """Build the Entra hint without claiming convergence.

        Args:
            target_upn: UPN hint when known.
            parts: Mutation facts (UPN fallback).

        Returns:
            Hint mapping for the cloud poller.
        """
        upn = target_upn or (parts.target_upn if parts else None)
        return EntraEvidenceHint(
            target_upn=upn, sync_scope_note="AD change committed; cloud poller must observe Entra separately"
        )
