"""Unit: transport retry/relay/worker branches, telemetry, tokens, entrypoints."""

import asyncio
import json
import random
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

import mwa_ad_connector.entrypoints.api as api_entry
import mwa_ad_connector.entrypoints.worker as worker_entry
from mwa_ad_connector.api import dependencies as deps
from mwa_ad_connector.api import error_handlers as handler_mod
from mwa_ad_connector.api.error_handlers import ConnectorError
from mwa_ad_connector.api.routes import execute_capability as route_execute
from mwa_ad_connector.api.schemas.common import create_page_token, verify_page_token
from mwa_ad_connector.infrastructure.telemetry import logging as tlog
from mwa_ad_connector.infrastructure.telemetry.metrics import ConnectorMetrics
from mwa_ad_connector.infrastructure.telemetry.tracing import get_tracer, trace_operation
from mwa_ad_connector.infrastructure.transport import relay as relay_mod
from mwa_ad_connector.infrastructure.transport.dead_letter import InMemoryDeadLetterStore, build_record, is_poison
from mwa_ad_connector.infrastructure.transport.relay import InMemoryRelay, ServiceBusRelay, TransportError
from mwa_ad_connector.infrastructure.transport.retry import (
    RetryBudget,
    RetryPolicy,
    classify_transport_error,
    compute_backoff_delay,
    is_retryable_category,
    is_retryable_code,
    run_with_retry,
)
from mwa_ad_connector.infrastructure.transport.worker import (
    CanonicalDispatcherAdapter,
    OperationServiceDispatcher,
    OutboundWorker,
    WorkerConfig,
    dedup_key,
    run_worker_forever,
    validate_envelope,
)
from tests.conftest import auth_headers, make_envelope, make_settings

_RNG = random.Random(0)  # noqa: S311 - deterministic jitter source for tests only.
_CANARY = "s3cret-canary"  # noqa: S105 - synthetic test canary, never a real credential.


def test_backoff_bounds_and_validation() -> None:
    """Backoff stays within [0, max]; invalid policies fail fast."""
    policy = RetryPolicy(max_attempts=3, base_delay_seconds=1.0, max_delay_seconds=4.0, jitter_ratio=0.0)
    assert compute_backoff_delay(policy, 1, _RNG) == 1.0
    assert compute_backoff_delay(policy, 2, _RNG) == 2.0
    assert compute_backoff_delay(policy, 10, _RNG) == 4.0
    assert compute_backoff_delay(policy, 1, _RNG) >= 0.0
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(base_delay_seconds=-1.0)
    with pytest.raises(ValueError):
        RetryPolicy(jitter_ratio=2.0)
    with pytest.raises(ValueError):
        RetryBudget(max_retries=-1)


def test_retryable_predicates() -> None:
    """Only dependency-side categories/codes are retryable."""
    assert is_retryable_category("DEPENDENCY") and is_retryable_category("TIMEOUT")
    assert not is_retryable_category("POLICY") and not is_retryable_category(None)
    assert is_retryable_code("LDAP_UNAVAILABLE") and is_retryable_code("RATE_LIMITED")
    assert not is_retryable_code("PROTECTED_TARGET") and not is_retryable_code(None)
    assert classify_transport_error(ConnectorError(code="LDAP_TIMEOUT", message="t"))["retryable"] is True
    assert classify_transport_error(ConnectorError(code="PROTECTED_TARGET", message="t"))["retryable"] is False
    assert classify_transport_error(ValueError("boom")) == {"retryable": False, "reason": "ValueError"}


def test_retry_budget_window() -> None:
    """Budget caps retries per window, then recovers."""
    budget = RetryBudget(max_retries=2, window_seconds=60.0)
    assert budget.try_consume(now=0.0) and budget.try_consume(now=1.0)
    assert budget.try_consume(now=2.0) is False
    assert budget.try_consume(now=61.0) is True


async def test_run_with_retry_paths() -> None:
    """Success first-try, retry-then-success, terminal immediately, budget stop."""
    calls = {"n": 0}

    async def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectorError(code="LDAP_UNAVAILABLE", message="down")
        return "ok"

    policy = RetryPolicy(max_attempts=3, base_delay_seconds=0.001, max_delay_seconds=0.002)
    assert await run_with_retry(flaky, policy, lambda e: True, rng=_RNG) == "ok"

    async def terminal() -> str:
        raise ConnectorError(code="PROTECTED_TARGET", message="no")

    with pytest.raises(ConnectorError):
        await run_with_retry(terminal, policy, lambda e: getattr(e, "code", "") == "LDAP_UNAVAILABLE")

    async def always() -> str:
        raise ConnectorError(code="LDAP_UNAVAILABLE", message="down")

    with pytest.raises(ConnectorError):
        await run_with_retry(always, policy, lambda e: True, budget=RetryBudget(max_retries=0))


async def test_relay_abandon_requeues_and_counts() -> None:
    """Abandoned messages redeliver with higher delivery count; counts tracked."""
    relay = InMemoryRelay()
    message_id = await relay.publish({"a": 1})
    first = await relay.receive()
    assert first is not None and relay.pending_count == 1
    await relay.abandon(first.message_id)
    assert relay.pending_count == 0 and relay.queued_count == 1
    second = await relay.receive()
    assert second is not None and second.delivery_count == 2 and second.message_id == message_id
    await relay.ack(second.message_id)
    assert relay.pending_count == 0 and message_id in relay.acked
    assert await relay.receive(timeout_seconds=0.01) is None


async def test_service_bus_stub_raises_transport_error() -> None:
    """ServiceBusRelay keeps the interface but refuses use until wired."""
    stub = ServiceBusRelay(fully_qualified_namespace="ns", queue_name="q")
    with pytest.raises(TransportError):
        await stub.receive()
    with pytest.raises(TransportError):
        await stub.ack("m")
    with pytest.raises(TransportError):
        await stub.abandon("m")
    with pytest.raises(TransportError):
        await stub.publish_result({})
    with pytest.raises(TransportError):
        await stub.publish({})


def test_dead_letter_helpers() -> None:
    """Poison predicate and redacted record building."""
    assert is_poison(5, 5) and not is_poison(1, 5) and is_poison(9, 0)
    record = build_record(
        message_id="m",
        reason="POISON",
        attempts=5,
        envelope={"new_password": _CANARY, "capability": "c"},
        correlation_id="corr",
    )
    assert record.payload_redacted["new_password"] == tlog.REDACTED_PLACEHOLDER
    assert record.capability == "c" and record.correlation_id == "corr"


async def test_worker_retryable_abandon_and_poison_dlq() -> None:
    """Retryable handler faults abandon; exhausted budget dead-letters."""
    relay = InMemoryRelay()
    attempts = {"n": 0}

    class Flaky:
        async def dispatch(self, envelope: Any) -> Any:
            attempts["n"] += 1
            raise ConnectorError(code="LDAP_UNAVAILABLE", message="down")

    open_worker = OutboundWorker(relay, Flaky(), WorkerConfig(max_delivery_attempts=5))
    await relay.publish(make_envelope())
    assert await open_worker.process_one() is True
    assert attempts["n"] == 1
    assert relay.queued_count == 1  # abandoned for redelivery, not dead-lettered.

    strict_store = InMemoryDeadLetterStore()
    strict_worker = OutboundWorker(
        InMemoryRelay(), Flaky(), WorkerConfig(max_delivery_attempts=1), dead_letter_store=strict_store
    )
    strict_relay = strict_worker._relay  # noqa: SLF001 - test-owned relay introspection.
    assert isinstance(strict_relay, InMemoryRelay)
    await strict_relay.publish(make_envelope())
    assert await strict_worker.process_one() is True
    assert await strict_store.count() == 1  # budget=1 already exhausted on first delivery.


async def test_operation_service_dispatcher_malformed() -> None:
    """Dispatcher adapter rejects mutation results that lack an operation id."""

    class Bad:
        async def execute_capability(self, **kwargs: Any) -> Any:
            return {"state": "AD_VERIFIED"}

    with pytest.raises(ValueError):
        await OperationServiceDispatcher(Bad()).dispatch({"capability": "account.unlock"})


async def test_canonical_adapter_round_trip() -> None:
    """Canonical adapter converts envelope model <-> MutationResult dict."""

    class FakeResult:
        def model_dump(self, mode: str = "json") -> dict[str, Any]:
            return {"operation_id": "op-9", "state": "AD_VERIFIED"}

    class FakeDispatcher:
        async def dispatch(self, envelope: Any, caller: Any) -> Any:
            assert envelope.capability == "account.unlock"
            return FakeResult()

    envelope = make_envelope(
        capability="account.unlock",
        target={
            "object_type": "USER",
            "object_guid": "91faf0e8-cfb6-49ea-80a7-e621986443f8",
            "domain_id": "domain-lab",
            "forest_id": "forest-lab",
        },
        parameters={},
    )
    result = await CanonicalDispatcherAdapter(FakeDispatcher(), caller_factory=lambda: {"sub": "t"}).dispatch(envelope)
    assert result["operation_id"] == "op-9"

    class BadResult:
        async def dispatch(self, envelope: Any, caller: Any) -> Any:
            return {"operation_id": ""}

    with pytest.raises(ValueError):
        await CanonicalDispatcherAdapter(BadResult(), caller_factory=lambda: None).dispatch(envelope)


async def test_run_worker_forever_requires_dispatcher() -> None:
    """Convenience runner refuses to start without a dispatcher (fail-closed)."""
    with pytest.raises(ValueError):
        await run_worker_forever(relay=InMemoryRelay(), dispatcher=None)


def test_validate_envelope_canonical_mismatch_paths() -> None:
    """Unknown capability and scope-mismatched targets are rejected."""
    with pytest.raises((ValidationError, ValueError)):
        validate_envelope(make_envelope(capability="ldap.raw.query"))
    target = {"object_type": "USER", "object_guid": "u-1", "domain_id": "other", "forest_id": "forest-lab"}
    with pytest.raises((ValidationError, ValueError)):
        validate_envelope(make_envelope(capability="account.unlock", target=target, parameters={}))
    assert dedup_key({"tenant_id": "t"}) is None


def test_page_token_lifecycle() -> None:
    """Round-trip works; tampered/malformed/expired tokens fail distinctly."""
    hmac_key = "token-test-signing-key"
    token = create_page_token({"offset": 3}, hmac_key, ttl_seconds=60)
    assert verify_page_token(token, hmac_key) == {"offset": 3}
    with pytest.raises(ValueError, match="PAGE_TOKEN_MALFORMED"):
        verify_page_token("no-dot", hmac_key)
    with pytest.raises(ValueError):  # garbage cursor rejected (malformed or invalid signature).
        verify_page_token("%%%.%%%", hmac_key)
    raw, _sig = token.split(".")
    with pytest.raises(ValueError, match="PAGE_TOKEN_INVALID"):
        verify_page_token(f"{raw}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", hmac_key)
    expired = create_page_token({"offset": 1}, hmac_key, ttl_seconds=-1)
    with pytest.raises(ValueError, match="PAGE_TOKEN_EXPIRED"):
        verify_page_token(expired, hmac_key)


def test_telemetry_logging_metrics_tracing() -> None:
    """Logging configures (json + console), metrics record, tracing is safe."""
    tlog.configure_logging(level="WARNING", json_output=True)
    logger = tlog.get_logger("test-component")
    logger.info("hello", ticket_id="T-1", result="ok")
    tlog.set_log_context(correlation_id="c-1", ticket_id="T-1")
    tlog.configure_logging(level="WARNING", json_output=False)
    assert tlog.redact_mapping({"a": 1}) == {"a": 1}

    metrics = ConnectorMetrics()
    metrics.observe_operation(capability="account.unlock", state="AD_VERIFIED", latency_seconds=-1.0)
    metrics.inc_verification_failure(capability="account.unlock")
    metrics.inc_worker_message(outcome="acked")
    metrics.inc_api_error(code="TARGET_NOT_FOUND")
    exposition = metrics.exposition().decode()
    assert "mwa_operations_total" in exposition and "mwa_api_errors_total" in exposition

    tracer = get_tracer("test-scope")
    assert tracer is not None
    with trace_operation("test-op", capability="account.unlock", count=1, skip={"nested": True}) as span:
        span.set_attribute("extra", "x")
        span.record_exception(ValueError("v"))


def test_entrypoints_wiring(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """API entrypoint launches uvicorn; worker relay selects via env; dispatcher fail-closed."""
    trust = tmp_path / "ca.pem"
    trust.write_text("fake-pem", encoding="utf-8")
    for key, value in {
        "MWA_AD_CUSTOMER_ID": "customer-lab",
        "MWA_AD_TENANT_ID": "tenant-lab",
        "MWA_AD_CONNECTOR_ID": "connector-lab-01",
        "MWA_AD_FOREST_ID": "forest-lab",
        "MWA_AD_DOMAIN_ID": "domain-lab",
        "MWA_AD_BASE_DN": "DC=lab,DC=local",
        "MWA_AD_MANAGED_OUS": '["OU=Managed,DC=lab,DC=local"]',
        "MWA_AD_DC_HOST": "dc01.lab.local",
        "MWA_AD_TRUST_STORE_PATH": str(trust),
        "MWA_AD_AUTH_MODE": "gmsa",
        "MWA_AD_JWT_SECRET": "test-only-jwt-secret",
        "MWA_AD_PAGE_TOKEN_SECRET": "test-only-page-secret",
        "MWA_AD_STATE_DIR": str(tmp_path / "state"),
    }.items():
        monkeypatch.setenv(key, value)
    launched: dict[str, Any] = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: launched.update(app=app, **kwargs))
    api_entry.main()
    assert launched["host"] == "127.0.0.1" and launched["port"] == 8443

    assert isinstance(worker_entry._build_relay(), InMemoryRelay)  # noqa: SLF001 - entrypoint seam check.
    monkeypatch.setenv("MWA_AD_SERVICEBUS_ENABLED", "true")
    monkeypatch.setenv("MWA_AD_SERVICEBUS_CONNECTION_STRING", "Endpoint=sb://unit.test/;SharedAccessKey=s3cr3t")
    assert isinstance(worker_entry._build_relay(), relay_mod.ServiceBusRelay)  # noqa: SLF001 - entrypoint seam check.


class _PagedService:
    """Search stub returning a continuation cursor plus an export receipt."""

    async def search_operations(self, *args: Any, **kwargs: Any) -> Any:
        """Return one page with a continuation cursor."""
        return {"items": [], "next_cursor": {"offset": 5}}

    async def export_audit(self, *args: Any, **kwargs: Any) -> Any:
        """Return an export receipt."""
        return {"export_id": "exp-9", "state": "RECEIVED"}


async def test_operation_search_next_page_and_audit_branches(client: TestClient, app: FastAPI) -> None:
    """Search continuation tokens, audit scope gate, and invalid export windows."""
    settings = make_settings()
    app.dependency_overrides[deps.get_operation_service] = _PagedService
    headers = auth_headers(settings)
    searched = client.post("/api/v1/operations:search", json={"filters": {}}, headers=headers)
    assert searched.status_code == 200 and searched.json()["next_page_token"]

    bad_token = client.post(
        "/api/v1/operations:search", json={"filters": {}, "page_token": "bad.token"}, headers=headers
    )
    assert bad_token.status_code == 400

    narrow = auth_headers(settings, scopes=["ad.operation.read"], include_idempotency=False, include_ticket=False)
    forbidden = client.post(
        "/api/v1/audit:export",
        json={
            "requested_from": "2026-01-01T00:00:00Z",
            "requested_to": "2026-02-01T00:00:00Z",
            "approval_id": "a",
        },
        headers=narrow,
    )
    assert forbidden.status_code == 403

    bad_window = client.post(
        "/api/v1/audit:export",
        json={
            "requested_from": "2026-02-01T00:00:00Z",
            "requested_to": "2026-01-01T00:00:00Z",
            "approval_id": "a",
        },
        headers=headers,
    )
    assert bad_window.status_code == 400


async def test_execute_helper_rejects_malformed() -> None:
    """Route helper maps malformed service results to 500 (never passthrough)."""

    class Empty:
        async def execute_capability(self, **kwargs: Any) -> Any:
            return {}

    class NotDict:
        async def execute_capability(self, **kwargs: Any) -> Any:
            return ["x"]

    with pytest.raises(ConnectorError) as exc_info:
        await route_execute(Empty(), capability="c", caller=None, idempotency_key=None, correlation_id="c")
    assert exc_info.value.code == "INTERNAL_ERROR"
    with pytest.raises(ConnectorError):
        await route_execute(
            NotDict(),
            capability="c",
            caller=None,
            idempotency_key=None,
            correlation_id="c",
            expect_operation=False,
        )


class _FailingReadiness:
    """Readiness stub simulating an unwired operation store."""

    async def get_readiness(self) -> Any:
        """Raise a retryable dependency fault."""
        raise ConnectorError(code="LDAP_UNAVAILABLE", message="down")


async def test_readiness_degraded_without_operation_service(client: TestClient, app: FastAPI) -> None:
    """Readiness reports unhealthy stores when the operation service is unwired."""
    app.dependency_overrides[deps.get_operation_service] = _FailingReadiness
    headers = auth_headers(
        make_settings(), scopes=["ad.readiness.read"], include_idempotency=False, include_ticket=False
    )
    response = client.get("/api/v1/readiness", headers=headers)
    assert response.status_code == 503
    assert response.json()["ready"] is False


def test_error_handler_branches() -> None:
    """Validation with empty locations and bare HTTP errors map stably."""

    class _App:
        state = type("S", (), {"metrics": None})()

    class _Request:
        state = type("ST", (), {"correlation_id": None})()
        headers: dict[str, str] = {}
        app = _App()

    empty = RequestValidationError([{"type": "missing", "loc": (), "msg": "x", "input": {}}])
    response = asyncio.run(handler_mod.validation_error_handler(_Request(), empty))  # type: ignore[arg-type]
    assert response.status_code == 400

    for status in (418, 503):
        http_response = asyncio.run(
            handler_mod.http_error_handler(_Request(), StarletteHTTPException(status_code=status))  # type: ignore[arg-type]
        )
        assert http_response.status_code == status
        body = json.loads(bytes(http_response.body).decode())
        assert body["error"]["code"] in ("REQUEST_INVALID", "INTERNAL_ERROR")

    unhandled = asyncio.run(handler_mod.unhandled_error_handler(_Request(), RuntimeError("x")))  # type: ignore[arg-type]
    assert unhandled.status_code == 500
    assert json.loads(bytes(unhandled.body).decode())["error"]["correlation_id"] is None
