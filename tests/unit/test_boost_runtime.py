"""Coverage boost: runtime health, entrypoints, dispatcher wiring, transport, operation store."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest
from pydantic import ValidationError

from mwa_ad_connector.application.commands import handlers as handlers_module
from mwa_ad_connector.application.commands.dispatcher import CommandDispatcher
from mwa_ad_connector.application.ports import clock as clock_module
from mwa_ad_connector.application.ports import command_transport as command_transport_module
from mwa_ad_connector.application.ports import nonce_store as nonce_store_module
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.domain.errors import RequestInvalidError
from mwa_ad_connector.entrypoints.worker import _build_dispatcher, _build_relay
from mwa_ad_connector.infrastructure.persistence.operation_store import InMemoryOperationStore
from mwa_ad_connector.infrastructure.transport.relay import InMemoryRelay, ServiceBusRelay
from mwa_ad_connector.infrastructure.transport.worker import (
    CanonicalDispatcherAdapter,
    OperationServiceDispatcher,
    WorkerConfig,
    dedup_key,
    validate_envelope,
)
from mwa_ad_connector.operations.idempotency import IdempotencyCollision
from mwa_ad_connector.runtime.health import collect_readiness


def _settings(**overrides: Any) -> ConnectorSettings:
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
        "jwt_secret": "boost-test-jwt-secret",  # noqa: S106 - test-only HMAC key.
        "page_token_secret": "boost-test-page-secret",  # noqa: S106 - test-only HMAC key.
    }
    values.update(overrides)
    return ConnectorSettings(**values)


def _envelope(**overrides: Any) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
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


class _OkOpStore:
    async def list(self, limit: int = 1) -> list[Any]:
        _ = limit
        return []


class _BadOpStore:
    async def list(self, limit: int = 1) -> list[Any]:
        _ = limit
        raise RuntimeError("store down")


class _OkAuditStore:
    async def export(self, limit: int = 1) -> dict[str, str]:
        _ = limit
        return {"export_id": "exp-1"}

    async def verify_chain(self) -> Any:
        return SimpleNamespace(valid=True, checked=7)


class _BrokenAuditStore(_OkAuditStore):
    async def verify_chain(self) -> Any:
        return SimpleNamespace(valid=False, checked=7)


class _NoChainAuditStore:
    async def export(self, limit: int = 1) -> dict[str, str]:
        _ = limit
        return {"export_id": "exp-1"}


class _OkGateway:
    async def ping(self) -> dict[str, Any]:
        return {"ok": True, "detail": "lab-dc"}


class _DownGateway:
    async def ping(self) -> dict[str, Any]:
        raise RuntimeError("dc down")


class _FakeOpService:
    async def execute_capability(  # noqa: PLR0913 - mirrors the service seam.
        self,
        *,
        capability: str,
        target: dict[str, Any],
        parameters: dict[str, Any],
        caller: Any,
        idempotency_key: str | None,
        correlation_id: str,
        ticket_id: str | None,
        dry_run: bool,
    ) -> dict[str, Any]:
        _ = (capability, parameters, caller, idempotency_key, correlation_id, ticket_id, dry_run)
        if not target.get("object_guid"):
            return {"state": "MALFORMED"}
        return {"operation_id": "op-9", "state": "AD_VERIFIED"}


async def test_readiness_all_healthy() -> None:
    checks = await collect_readiness(
        settings=_settings(),
        gateway=_OkGateway(),
        operation_store=_OkOpStore(),
        audit_store=_OkAuditStore(),
        timeout=1.0,
    )
    assert len(checks) == 6
    assert all(check["healthy"] for check in checks)


async def test_readiness_faults_fail_closed() -> None:
    checks = await collect_readiness(
        settings=_settings(),
        gateway=_DownGateway(),
        operation_store=_BadOpStore(),
        audit_store=_NoChainAuditStore(),
        timeout=0.01,
    )
    by_name = {check["name"]: check for check in checks}
    assert by_name["operation_store"]["healthy"] is False
    assert by_name["ldap_connectivity"]["healthy"] is False
    assert by_name["audit_chain"]["healthy"] is False


async def test_readiness_broken_chain_and_no_ping() -> None:
    checks = await collect_readiness(
        settings=_settings(),
        gateway=object(),
        operation_store=_OkOpStore(),
        audit_store=_BrokenAuditStore(),
        timeout=1.0,
    )
    by_name = {check["name"]: check for check in checks}
    assert by_name["ldap_connectivity"]["detail"] == "gateway_without_ping"
    assert by_name["audit_chain"]["healthy"] is False


def test_ports_modules_importable() -> None:
    assert clock_module.Clock is not None
    assert nonce_store_module.NonceStore is not None
    assert command_transport_module is not None
    assert handlers_module is not None


def test_entrypoint_relay_selection(monkeypatch: Any) -> None:
    assert isinstance(_build_relay(_settings()), InMemoryRelay)
    enabled = _settings(
        servicebus_enabled=True,
        servicebus_connection_string="Endpoint=sb://unit.test/;SharedAccessKey=s3cr3t",
    )
    assert isinstance(_build_relay(enabled), ServiceBusRelay)

    def _boom(settings: Any) -> Any:
        raise ValueError("assembly failed")

    monkeypatch.setattr("mwa_ad_connector.entrypoints.worker.build_runtime", _boom)
    with pytest.raises(RuntimeError):
        _build_dispatcher(_settings())


def test_command_dispatcher_register() -> None:
    dispatcher = CommandDispatcher(cast(Any, object()))

    async def _executor(request: Any, caller: Any) -> Any:
        _ = (request, caller)
        raise AssertionError("must not run")

    with pytest.raises(RequestInvalidError):
        dispatcher.register("not.a.capability", _executor)
    dispatcher.register("account.unlock", _executor)


async def test_transport_dispatch_and_validate() -> None:
    adapter = OperationServiceDispatcher(cast(Any, _FakeOpService()))
    envelope = _envelope()
    result = await adapter.dispatch(envelope)
    assert result["operation_id"] == "op-9"
    with pytest.raises(ValueError, match="malformed"):
        await adapter.dispatch({**envelope, "target": {}})

    validated = validate_envelope(envelope)
    assert validated["capability"] == envelope["capability"]
    with pytest.raises(ValidationError):
        validate_envelope({"capability": "nope"})
    assert WorkerConfig().poll_timeout_seconds == 1.0
    assert dedup_key({}) is None

    seen: list[str] = []

    class _Canonical:
        async def dispatch(self, model: Any, caller: Any) -> dict[str, Any]:
            _ = (model, caller)
            seen.append("called")
            return {"operation_id": "op-1", "state": "AD_VERIFIED"}

    canonical = CanonicalDispatcherAdapter(_Canonical(), lambda: {"subject": "worker"})
    out = await canonical.dispatch(envelope)
    assert out["state"] == "AD_VERIFIED"
    assert seen == ["called"]


async def test_operation_store_reserve_and_list() -> None:
    store = InMemoryOperationStore()
    try:
        stored, created = await store.reserve(
            tenant_id="t", connector_id="c", idempotency_key="k1", request_hash="h1", operation_id="op-1"
        )
        assert created is True
        assert stored.operation_id == "op-1"
        _, created2 = await store.reserve(
            tenant_id="t", connector_id="c", idempotency_key="k1", request_hash="h1", operation_id="op-1"
        )
        assert created2 is False
        with pytest.raises(IdempotencyCollision):
            await store.reserve(
                tenant_id="t", connector_id="c", idempotency_key="k1", request_hash="other", operation_id="op-2"
            )
        items = await store.list(limit=1)
        assert len(items) >= 1
    finally:
        store.close()
