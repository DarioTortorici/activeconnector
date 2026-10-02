"""Unit: worker publishes correlated results and entrypoint selects the relay/runtime.

Covers Task 4 of the S2 plan: ``process_one`` must publish the envelope
``correlation_id`` plus the relay ``message_id`` (envelope correlation wins over
any stale value already present in the dispatcher result), and the worker
entrypoint must build the real runtime and pick Service Bus only when configured.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

import mwa_ad_connector.entrypoints.worker as worker_entry
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.infrastructure.transport.relay import InMemoryRelay, ServiceBusRelay
from mwa_ad_connector.infrastructure.transport.worker import (
    OperationServiceDispatcher,
    OutboundWorker,
    WorkerConfig,
)

CONNECTION_STRING = "Endpoint=sb://unit.test/;SharedAccessKeyName=k;SharedAccessKey=s3cr3t"


def _envelope(**overrides: Any) -> dict[str, Any]:
    """Build a canonical mutation envelope valid for the worker validator."""
    now = datetime.now(UTC)
    envelope: dict[str, Any] = {
        "schema_version": "1.0",
        "capability": "group.member.add",
        "customer_id": "customer-lab",
        "tenant_id": "tenant-lab",
        "connector_id": "connector-lab-01",
        "forest_id": "forest-lab",
        "domain_id": "domain-lab",
        "target": {
            "object_type": "GROUP",
            "object_guid": "7e565f72-8274-4cb8-b77a-7dad17a1b432",
            "domain_id": "domain-lab",
            "forest_id": "forest-lab",
        },
        "parameters": {"member": {"object_type": "USER", "object_guid": "91faf0e8-cfb6-49ea-80a7-e621986443f8"}},
        "dry_run": False,
        "idempotency_key": uuid4().hex,
        "correlation_id": uuid4().hex,
        "ticket_id": "TICKET-123",
        "requested_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "nonce": uuid4().hex,
        "requested_by": "test-caller",
    }
    envelope.update(overrides)
    return envelope


def _settings(**overrides: Any) -> ConnectorSettings:
    """Build minimal valid connector settings for entrypoint-selection tests."""
    values: dict[str, Any] = {
        "customer_id": "cust-lab",
        "tenant_id": "tenant-lab",
        "connector_id": "connector-lab-01",
        "forest_id": "forest-lab",
        "domain_id": "domain-lab",
        "base_dn": "DC=lab,DC=local",
        "managed_ous": ["OU=Users,DC=lab,DC=local"],
        "dc_host": "dc-lab.local",
        "ldaps_require_cert": False,
        "jwt_secret": "unit-test-jwt-secret",  # noqa: S106 - test-only HMAC key.
        "page_token_secret": "unit-test-page-secret",  # noqa: S106 - test-only HMAC key.
    }
    values.update(overrides)
    return ConnectorSettings(**values)


class _FakeDispatcher:
    """Dispatcher double recording calls and returning a fixed result."""

    def __init__(self, result: dict[str, Any]) -> None:
        self._result = result
        self.calls: list[dict[str, Any]] = []

    async def dispatch(self, envelope: Any) -> dict[str, Any]:
        self.calls.append(dict(envelope))
        return dict(self._result)


async def test_process_one_publishes_correlation_and_message_id() -> None:
    """The published result carries the envelope correlation and relay message id."""
    relay = InMemoryRelay()
    envelope = _envelope()
    dispatcher = _FakeDispatcher({"operation_id": "op-1", "state": "AD_VERIFIED"})
    worker = OutboundWorker(relay, dispatcher, WorkerConfig(poll_timeout_seconds=0.01))
    message_id = await relay.publish(envelope)

    handled = await worker.process_one()

    assert handled is True
    published = relay.results[-1]
    assert published["correlation_id"] == envelope["correlation_id"]
    assert published["message_id"] == message_id
    assert published["state"] == "AD_VERIFIED"
    assert published["operation_id"] == "op-1"


async def test_envelope_correlation_wins_over_stale_result_values() -> None:
    """An envelope correlation id overrides a stale one; relay message id wins too."""
    relay = InMemoryRelay()
    envelope = _envelope(correlation_id="env-correlation")
    dispatcher = _FakeDispatcher(
        {
            "operation_id": "op-2",
            "state": "AD_VERIFIED",
            "correlation_id": "stale-result-correlation",
            "message_id": "stale-result-message",
        }
    )
    worker = OutboundWorker(relay, dispatcher, WorkerConfig(poll_timeout_seconds=0.01))
    message_id = await relay.publish(envelope)

    await worker.process_one()

    published = relay.results[-1]
    assert published["correlation_id"] == "env-correlation"
    assert published["message_id"] == message_id
    assert published["state"] == "AD_VERIFIED"


async def test_duplicate_delivery_publishes_correlated_result_with_current_message_id() -> None:
    """The dedup path re-stamps the current relay message id on the cached result."""
    relay = InMemoryRelay()
    envelope = _envelope(idempotency_key="idem-fixed-0001")
    dispatcher = _FakeDispatcher({"operation_id": "op-3", "state": "AD_VERIFIED"})
    worker = OutboundWorker(relay, dispatcher, WorkerConfig(poll_timeout_seconds=0.01))
    first_id = await relay.publish(envelope)
    second_id = await relay.publish(envelope)

    await worker.process_one()
    await worker.process_one()

    assert len(dispatcher.calls) == 1
    assert relay.results[0]["correlation_id"] == envelope["correlation_id"]
    assert relay.results[0]["message_id"] == first_id
    assert relay.results[1]["correlation_id"] == envelope["correlation_id"]
    assert relay.results[1]["message_id"] == second_id


def test_build_relay_defaults_to_in_memory() -> None:
    """Service Bus disabled (or unconfigured) selects the in-memory relay."""
    assert isinstance(worker_entry._build_relay(_settings()), InMemoryRelay)  # noqa: SLF001


def test_build_relay_selects_service_bus_when_enabled() -> None:
    """Service Bus enabled with a connection string selects the real relay."""
    settings = _settings(
        servicebus_enabled=True,
        servicebus_connection_string=CONNECTION_STRING,
        servicebus_command_queue="cmd-q",
        servicebus_result_queue="res-q",
    )

    relay = worker_entry._build_relay(settings)  # noqa: SLF001

    assert isinstance(relay, ServiceBusRelay)
    assert relay.connection_string == CONNECTION_STRING
    assert relay.command_queue == "cmd-q"
    assert relay.result_queue == "res-q"


def test_build_dispatcher_uses_build_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """The dispatcher is built over ``composition.build_runtime(...).api_service``."""
    captured: dict[str, Any] = {}

    class _Runtime:
        api_service = object()

    def _fake_build(settings: ConnectorSettings) -> _Runtime:
        captured["settings"] = settings
        return _Runtime()

    monkeypatch.setattr(worker_entry, "build_runtime", _fake_build)
    settings = _settings()

    dispatcher = worker_entry._build_dispatcher(settings)  # noqa: SLF001

    assert isinstance(dispatcher, OperationServiceDispatcher)
    assert captured["settings"] is settings


def test_build_dispatcher_fails_closed_on_assembly_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An assembly fault is re-raised as a fail-closed RuntimeError."""

    def _boom(settings: ConnectorSettings) -> None:
        raise ValueError("assembly failed")

    monkeypatch.setattr(worker_entry, "build_runtime", _boom)

    with pytest.raises(RuntimeError):
        worker_entry._build_dispatcher(_settings())  # noqa: SLF001


async def test_close_relay_awaits_async_close_and_swallows_errors() -> None:
    """The shutdown helper closes async relays best-effort and never raises."""
    closed: list[str] = []

    class _AsyncRelay:
        async def close(self) -> None:
            closed.append("async")

    class _SyncRelay:
        def close(self) -> None:
            closed.append("sync")

    class _BadRelay:
        async def close(self) -> None:
            raise RuntimeError("close failed")

    await worker_entry._close_relay(_AsyncRelay())  # noqa: SLF001
    await worker_entry._close_relay(_SyncRelay())  # noqa: SLF001
    await worker_entry._close_relay(_BadRelay())  # noqa: SLF001
    await worker_entry._close_relay(InMemoryRelay())  # noqa: SLF001

    assert closed == ["async", "sync"]
