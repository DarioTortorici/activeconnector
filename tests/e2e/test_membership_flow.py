"""E2E (fake transport+service): envelope -> worker -> verify -> published result."""

import asyncio
from typing import Any

import pytest

from mwa_ad_connector.infrastructure.telemetry.metrics import ConnectorMetrics
from mwa_ad_connector.infrastructure.transport.relay import InMemoryRelay
from mwa_ad_connector.infrastructure.transport.worker import (
    OperationServiceDispatcher,
    OutboundWorker,
    WorkerConfig,
)
from tests.conftest import FAILED_VERIFY_GUID

pytestmark = pytest.mark.e2e


async def _drain(worker: OutboundWorker, expected: int) -> None:
    """Process messages until the relay has published `expected` results."""
    relay = worker._relay  # noqa: SLF001 - test introspection of the test-owned relay.
    assert isinstance(relay, InMemoryRelay)
    for _ in range(50):
        await worker.process_one()
        if len(relay.results) >= expected:
            return
    raise AssertionError("Worker did not publish the expected results in time.")


async def test_membership_flow_envelope_to_verified_result(
    fake_service: Any, tenant_id: str, connector_id: str, envelope_factory: Any
) -> None:
    """Happy path: group.member.add envelope ends AD_VERIFIED and acked."""
    make_envelope = envelope_factory
    relay = InMemoryRelay()
    metrics = ConnectorMetrics()
    worker = OutboundWorker(
        relay,
        OperationServiceDispatcher(fake_service),
        WorkerConfig(expected_tenant_id=tenant_id, expected_connector_id=connector_id),
        metrics=metrics,
    )
    message_id = await relay.publish(make_envelope())
    await _drain(worker, 1)

    assert message_id in relay.acked
    result = relay.results[0]
    assert result["state"] == "AD_VERIFIED"
    assert result["disposition"] == "APPLIED"
    assert result["verification_evidence"]["matched"] is True
    assert "new_password" not in result

    exposition = metrics.exposition().decode()
    assert "mwa_operations_total" in exposition
    assert "mwa_worker_messages_total" in exposition


async def test_duplicate_delivery_does_not_re_execute(
    fake_service: Any, tenant_id: str, connector_id: str, envelope_factory: Any
) -> None:
    """At-least-once redelivery with the same key returns cached result (no 2nd LDAP write)."""
    make_envelope = envelope_factory
    relay = InMemoryRelay()
    worker = OutboundWorker(
        relay,
        OperationServiceDispatcher(fake_service),
        WorkerConfig(expected_tenant_id=tenant_id, expected_connector_id=connector_id),
    )
    envelope = make_envelope()
    await relay.publish(envelope)
    await relay.publish(dict(envelope))  # duplicate delivery, same idempotency key.
    await _drain(worker, 2)

    assert len(relay.results) == 2
    assert relay.results[0]["operation_id"] == relay.results[1]["operation_id"]
    group_adds = [e for e in fake_service.executed if e["capability"] == "group.member.add"]
    assert len(group_adds) == 1, "Duplicate delivery must not execute twice."


async def test_failed_verification_publishes_evidence(
    fake_service: Any, tenant_id: str, connector_id: str, envelope_factory: Any
) -> None:
    """Commit-ok/verify-fail path publishes FAILED_VERIFICATION with redacted evidence."""
    make_envelope = envelope_factory
    relay = InMemoryRelay()
    worker = OutboundWorker(
        relay,
        OperationServiceDispatcher(fake_service),
        WorkerConfig(expected_tenant_id=tenant_id, expected_connector_id=connector_id),
    )
    target = {
        "object_type": "GROUP",
        "object_guid": FAILED_VERIFY_GUID,
        "domain_id": "domain-lab",
        "forest_id": "forest-lab",
    }
    envelope = make_envelope(target=target, parameters={"member": {"object_type": "USER", "object_guid": "u-1"}})
    await relay.publish(envelope)
    await _drain(worker, 1)

    result = relay.results[0]
    assert result["state"] == "FAILED_VERIFICATION"
    assert result["verification_evidence"]["matched"] is False
    assert result["verification_evidence"]["redaction_applied"] is True


async def test_malformed_and_misbound_envelopes_dead_lettered(
    fake_service: Any, tenant_id: str, connector_id: str, envelope_factory: Any
) -> None:
    """Malformed and cross-tenant envelopes are quarantined (never dispatched)."""
    make_envelope = envelope_factory
    relay = InMemoryRelay()
    dlq_holder: dict[str, Any] = {}
    worker = OutboundWorker(
        relay,
        OperationServiceDispatcher(fake_service),
        WorkerConfig(expected_tenant_id=tenant_id, expected_connector_id=connector_id),
    )
    dlq_holder["store"] = worker._dlq  # noqa: SLF001 - test introspection.

    await relay.publish({"capability": "group.member.add"})  # malformed: missing required fields.
    await relay.publish(make_envelope(tenant_id="tenant-evil"))  # binding mismatch.
    for _ in range(50):
        await worker.process_one()
        if await dlq_holder["store"].count() >= 2:
            break

    assert await dlq_holder["store"].count() == 2
    assert fake_service.executed == [], "Quarantined envelopes must never execute."
    assert len(relay.results) == 0


async def test_worker_graceful_stop(fake_service: Any) -> None:
    """stop() lets the run loop exit without dropping the in-flight message."""
    relay = InMemoryRelay()
    worker = OutboundWorker(relay, OperationServiceDispatcher(fake_service), WorkerConfig())
    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.05)
    worker.stop()
    await asyncio.wait_for(task, timeout=5.0)
    assert task.done()
