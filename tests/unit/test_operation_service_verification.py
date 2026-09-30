"""Regression: commit-then-verify failure must surface as FAILED_VERIFICATION.

The membership service performs its own read-after-write inside the mutate
callback; when that verification fails the orchestrator cannot observe the
commit, but the operation must be recorded as FAILED_VERIFICATION (502),
never as a plain pre-commit FAILED.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from mwa_ad_connector.application.services.operation_service import MutationParts, OperationService
from mwa_ad_connector.domain.enums import MutationDisposition, ObjectType, OperationState
from mwa_ad_connector.domain.errors import VerificationFailedError
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.domain.operations import CallerContext, CapabilityRequest
from mwa_ad_connector.infrastructure.persistence.operation_store import InMemoryOperationStore
from mwa_ad_connector.runtime.adapters import OperationRepositoryAdapter


class RecordingAudit:
    """Minimal audit sink capturing redacted event outcomes."""

    def __init__(self) -> None:
        """Start with an empty event list."""
        self.events: list[dict[str, object]] = []

    async def append(  # noqa: PLR0913 - mirrors the canonical audit port signature.
        self,
        operation_id: str,
        capability: str,
        tenant_id: str,
        connector_id: str,
        caller_subject: str,
        target_guid: UUID | None,
        outcome: str,
        redacted_details: dict[str, str],
        occurred_at: datetime,
    ) -> str:
        """Record one audit event and return its id."""
        self.events.append(
            {
                "operation_id": operation_id,
                "capability": capability,
                "tenant_id": tenant_id,
                "connector_id": connector_id,
                "caller_subject": caller_subject,
                "target_guid": target_guid,
                "outcome": outcome,
                "redacted_details": redacted_details,
                "occurred_at": occurred_at,
            }
        )
        return f"audit-{len(self.events)}"

    async def get(self, audit_id: str) -> dict[str, str] | None:
        """Return a redacted audit record for the given id (minimal port shape)."""
        for event in self.events:
            if audit_id == f"audit-{self.events.index(event) + 1}":
                return {"audit_id": audit_id, "outcome": str(event["outcome"])}
        return None


def _request(target_guid: UUID, *, dry_run: bool = False, member_guid: UUID | None = None) -> CapabilityRequest:
    now = datetime.now(UTC)
    return CapabilityRequest(
        capability="group.member.add",
        customer_id="customer-lab",
        tenant_id="tenant-lab",
        connector_id="connector-lab-01",
        forest_id="forest-lab",
        domain_id="domain-lab",
        target=ObjectReference(
            object_type=ObjectType.GROUP,
            object_guid=target_guid,
            domain_id="domain-lab",
            forest_id="forest-lab",
        ),
        parameters={"member_guid": str(member_guid or uuid4())},
        dry_run=dry_run,
        idempotency_key="lab-key-0001",
        correlation_id="corr-1",
        ticket_id="LAB-1",
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        nonce="nonce-12345678",
        requested_by="tester",
    )


def _caller() -> CallerContext:
    return CallerContext(
        subject="tester",
        issuer="lab",
        audience="connector-lab-01",
        tenant_id="tenant-lab",
        customer_id="customer-lab",
        connector_id="connector-lab-01",
        auth_method="test",
        token_id="token-1",  # noqa: S106 - test fixture value, not a credential
        authenticated_at=datetime.now(UTC),
    )


async def test_verification_failed_after_commit_is_failed_verification() -> None:
    store = InMemoryOperationStore()
    audit = RecordingAudit()
    service = OperationService(OperationRepositoryAdapter(store), audit, source_dc="dc-lab")
    target_guid = uuid4()

    async def mutate() -> MutationParts:
        raise VerificationFailedError("member not observed after add")

    result = await service.execute(_request(target_guid), _caller(), mutate)

    assert result.state == OperationState.FAILED_VERIFICATION
    assert result.disposition == MutationDisposition.APPLIED
    assert result.target_object_guid == target_guid

    stored = await store.get(result.operation_id)
    assert stored is not None
    assert stored.state == OperationState.FAILED_VERIFICATION
    assert any(event["outcome"] == "FAILED_VERIFICATION" for event in audit.events)


async def test_precommit_failure_stays_failed() -> None:
    store = InMemoryOperationStore()
    audit = RecordingAudit()
    repository = OperationRepositoryAdapter(store)
    service = OperationService(repository, audit, source_dc="dc-lab")

    async def mutate() -> MutationParts:
        raise RuntimeError("connection refused before commit")

    request = _request(uuid4())
    try:
        await service.execute(request, _caller(), mutate)
    except RuntimeError:
        pass
    else:  # pragma: no cover - the orchestrator must re-raise pre-commit failures
        raise AssertionError("pre-commit failure must be re-raised")

    stored = await repository.get_by_idempotency_key("tenant-lab", "connector-lab-01", "lab-key-0001")
    assert stored is not None
    assert stored.state == OperationState.FAILED
    assert any(event["outcome"] == "FAILED" for event in audit.events)


async def test_replay_after_restart_without_persisted_dc_is_valid() -> None:
    """Replays rebuild the DC label when the persisted row lacks selected_dc."""
    store = InMemoryOperationStore()
    audit = RecordingAudit()
    target_guid = uuid4()
    member_guid = uuid4()

    async def no_mutate() -> MutationParts:
        raise AssertionError("dry-run must not mutate")

    first_service = OperationService(OperationRepositoryAdapter(store), audit, source_dc="dc-lab")
    first = await first_service.execute(
        _request(target_guid, dry_run=True, member_guid=member_guid), _caller(), no_mutate
    )
    assert first.state == OperationState.AUTHORIZED

    restarted_service = OperationService(OperationRepositoryAdapter(store), audit, source_dc="dc-lab")
    replay = await restarted_service.execute(
        _request(target_guid, dry_run=True, member_guid=member_guid), _caller(), no_mutate
    )
    assert replay.operation_id == first.operation_id
    assert replay.source_dc == "dc-lab"
    assert replay.disposition == MutationDisposition.NO_OP
