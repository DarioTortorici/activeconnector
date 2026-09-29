"""Outbound worker (Step 16): poll, validate, dedup, dispatch, publish, ack.

At-least-once safety: a message is acked only after its result is published.
Redeliveries never re-execute while the (tenant, connector, idempotency key)
dedup cache holds the result; beyond that, service-level idempotency owns
exactly-once execution. No inbound ports are required.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mwa_ad_connector.infrastructure.telemetry.logging import get_logger, redact_mapping, set_log_context
from mwa_ad_connector.infrastructure.transport.dead_letter import (
    DeadLetterStore,
    InMemoryDeadLetterStore,
    build_record,
    is_poison,
)
from mwa_ad_connector.infrastructure.transport.relay import InMemoryRelay, RelayMessage, RelayTransport
from mwa_ad_connector.infrastructure.transport.retry import RetryPolicy, classify_transport_error

try:  # Canonical envelope (Step 10/16 command track); local fallback below.
    from mwa_ad_connector.application.commands.envelope import CommandEnvelope as _CanonicalEnvelope
except ImportError:  # pragma: no cover
    _CanonicalEnvelope = None  # type: ignore[assignment, misc]

logger = get_logger("worker")

ENVELOPE_SCHEMA_VERSION = "1.0"


class WorkerEnvelope(BaseModel):
    """Local command-envelope validation (mirrors the canonical model when absent).

    Field set intentionally matches the canonical CommandEnvelope so envelopes
    built for production also validate on this fallback path.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern="^1\\.0$")
    capability: str = Field(min_length=1, max_length=128)
    customer_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    connector_id: str = Field(min_length=1, max_length=128)
    forest_id: str = Field(min_length=1, max_length=128)
    domain_id: str = Field(min_length=1, max_length=128)
    target: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    ticket_id: str | None = Field(default=None, max_length=128)
    requested_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=8, max_length=128)
    approval_context: dict[str, Any] | None = None
    expected_version: str | None = Field(default=None, max_length=256)
    requested_by: str = Field(min_length=1, max_length=256)


class CommandDispatcher(Protocol):
    """Execution seam: validated envelope dict in, result mapping out."""

    async def dispatch(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        """Execute one envelope; returns {operation_id, state, ...} (redacted)."""
        ...  # pragma: no cover


class OperationServiceDispatcher:
    """Dispatcher adapter over anything exposing execute_capability (services seam)."""

    def __init__(self, operation_service: Any) -> None:
        """Bind the operation service used for execution.

        Args:
            operation_service: Object with execute_capability(...) (canonical or fake).
        """
        self._service = operation_service

    async def dispatch(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        """Execute the envelope capability via the operation service."""
        target = dict(envelope.get("target") or {})
        parameters = dict(envelope.get("parameters") or {})
        result = await self._service.execute_capability(
            capability=str(envelope.get("capability")),
            target=target,
            parameters=parameters,
            caller={"subject": "worker", "transport": "relay"},
            idempotency_key=envelope.get("idempotency_key"),
            correlation_id=str(envelope.get("correlation_id") or "unknown"),
            ticket_id=envelope.get("ticket_id"),
            dry_run=bool(envelope.get("dry_run", False)),
        )
        if not isinstance(result, dict) or not result.get("operation_id"):
            raise ValueError("Dispatcher returned a malformed result.")
        return result


class CanonicalDispatcherAdapter:
    """Adapt the canonical orchestrating dispatcher to the worker dict seam.

    Wraps ``application.commands.dispatcher.CommandDispatcher`` (envelope model
    in, MutationResult out) behind the worker ``CommandDispatcher`` protocol
    (validated dict in, result dict out) with a system caller identity.
    """

    def __init__(self, dispatcher: Any, caller_factory: Any) -> None:
        """Bind the canonical dispatcher and caller factory.

        Args:
            dispatcher: Canonical CommandDispatcher (assembled by the services track).
            caller_factory: Zero-arg callable returning the CallerContext the
                canonical dispatcher requires (identity semantics owned by the
                assembly site, not invented here).
        """
        self._dispatcher = dispatcher
        self._caller_factory = caller_factory

    def _caller(self, envelope: Mapping[str, Any]) -> Any:
        """Return the assembly-provided caller for a relay envelope."""
        _ = envelope
        return self._caller_factory()

    async def dispatch(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        """Dispatch via the canonical dispatcher, returning a redacted result dict."""
        if _CanonicalEnvelope is None:  # pragma: no cover - canonical track always present in practice.
            raise ValueError("Canonical envelope model is unavailable.")
        model = _CanonicalEnvelope(**dict(envelope))
        result = await self._dispatcher.dispatch(model, self._caller(envelope))
        dumped = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
        if not dumped.get("operation_id") or not dumped.get("state"):
            raise ValueError("Canonical dispatcher returned a malformed MutationResult.")
        return dumped


@dataclass
class WorkerConfig:
    """Worker tuning and binding expectations."""

    poll_timeout_seconds: float = 1.0
    max_delivery_attempts: int = 5
    expected_tenant_id: str | None = None
    expected_connector_id: str | None = None
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)


def validate_envelope(data: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a raw envelope dict (canonical model when available).

    Args:
        data: Raw envelope mapping from the relay.

    Returns:
        Validated envelope as a plain dict.

    Raises:
        ValidationError: When the envelope is malformed.
        ValueError: When expires_at <= requested_at.
    """
    if _CanonicalEnvelope is not None:
        try:
            canonical_model: BaseModel = _CanonicalEnvelope(**dict(data))
            canonical_dumped = canonical_model.model_dump(mode="json")
            return canonical_dumped if isinstance(canonical_dumped, dict) else dict(data)
        except ValidationError:
            raise
        except Exception as exc:  # noqa: BLE001 - canonical shape mismatch falls back.
            raise ValueError(f"Envelope incompatible with canonical model: {exc}") from exc
    model = WorkerEnvelope(**dict(data))
    dumped: dict[str, Any] = model.model_dump(mode="json")
    if model.expires_at <= model.requested_at:
        raise ValueError("expires_at must be after requested_at.")
    if model.expires_at < datetime.now(UTC):
        raise ValueError("Envelope expired.")
    return dumped


def dedup_key(envelope: Mapping[str, Any]) -> str | None:
    """Build the intra-process dedup key, or None when the envelope lacks one."""
    key = envelope.get("idempotency_key")
    if not key:
        return None
    return f"{envelope.get('tenant_id')}|{envelope.get('connector_id')}|{key}"


class OutboundWorker:
    """Poll loop turning relay envelopes into published, redacted results."""

    def __init__(
        self,
        relay: RelayTransport,
        dispatcher: CommandDispatcher,
        config: WorkerConfig | None = None,
        dead_letter_store: DeadLetterStore | None = None,
        metrics: Any | None = None,
    ) -> None:
        """Wire the worker.

        Args:
            relay: Swappable relay transport (receive/ack/publish).
            dispatcher: Validated-envelope executor.
            config: Tuning and tenant/connector binding expectations.
            dead_letter_store: Quarantine for poison/malformed messages.
            metrics: Optional ConnectorMetrics for worker_messages_total.
        """
        self._relay = relay
        self._dispatcher = dispatcher
        self._config = config or WorkerConfig()
        self._dlq = dead_letter_store or InMemoryDeadLetterStore()
        self._metrics = metrics
        self._stop = asyncio.Event()
        self._dedup: dict[str, dict[str, Any]] = {}

    def stop(self) -> None:
        """Request graceful shutdown (in-flight message completes first)."""
        self._stop.set()

    def _metric(self, outcome: str) -> None:
        """Best-effort worker message counter."""
        if self._metrics is None:
            return
        with suppress(Exception):
            self._metrics.inc_worker_message(outcome=outcome)

    async def _dead_letter(self, message: RelayMessage, reason: str, envelope: Mapping[str, Any]) -> None:
        """Quarantine a message with redacted payload, then ack it."""
        record = build_record(
            message_id=message.message_id,
            reason=reason,
            attempts=message.delivery_count,
            envelope=dict(envelope) if isinstance(envelope, dict) else {},
            correlation_id=envelope.get("correlation_id") if isinstance(envelope, dict) else None,
        )
        await self._dlq.put(record)
        await self._relay.ack(message.message_id)
        self._metric("dead_lettered")
        logger.warning("message dead-lettered", reason=reason, message_id=message.message_id)

    def _binding_error(self, envelope: Mapping[str, Any]) -> str | None:
        """Check tenant/connector binding; returns a reason or None when bound."""
        if self._config.expected_tenant_id and envelope.get("tenant_id") != self._config.expected_tenant_id:
            return "TENANT_BINDING_MISMATCH"
        if self._config.expected_connector_id and envelope.get("connector_id") != self._config.expected_connector_id:
            return "CONNECTOR_BINDING_MISMATCH"
        return None

    async def _handle_dispatch_error(self, message: RelayMessage, envelope: Mapping[str, Any], exc: Exception) -> None:
        """Abandon retryable failures or dead-letter terminal ones (at-least-once safe)."""
        classification = classify_transport_error(exc)
        if classification["retryable"] and not is_poison(
            message.delivery_count + 1, self._config.max_delivery_attempts
        ):
            await self._relay.abandon(message.message_id)
            self._metric("retried")
            logger.warning("transient failure, message abandoned", reason=classification["reason"])
        else:
            await self._dead_letter(message, f"HANDLER_{classification['reason']}", envelope)

    async def _observe_success(self, envelope: Mapping[str, Any], latency: float, state: str) -> None:
        """Best-effort success observation (never breaks the ack path)."""
        if self._metrics is None:
            return
        with suppress(Exception):
            self._metrics.observe_operation(
                capability=str(envelope.get("capability")),
                state=state,
                latency_seconds=latency,
            )

    async def _prepare(self, message: RelayMessage) -> tuple[dict[str, Any], str | None] | None:
        """Validate, bind-check and poison-check one message (dead-lettering rejects).

        Returns:
            (envelope, dedup_key) when the message may execute, None when settled.
        """
        raw = message.envelope if isinstance(message.envelope, dict) else {}
        set_log_context(correlation_id=str(raw.get("correlation_id") or message.message_id))
        try:
            envelope = validate_envelope(raw)
        except (ValidationError, ValueError, TypeError) as exc:
            logger.warning("malformed envelope", error=type(exc).__name__)
            await self._dead_letter(message, "ENVELOPE_INVALID", raw if isinstance(raw, dict) else {})
            return None
        binding_error = self._binding_error(envelope)
        if binding_error:
            logger.warning("envelope binding mismatch", reason=binding_error)
            await self._dead_letter(message, binding_error, envelope)
            return None
        if is_poison(message.delivery_count, self._config.max_delivery_attempts):
            await self._dead_letter(message, "POISON_DELIVERY_BUDGET_EXHAUSTED", envelope)
            return None
        return envelope, dedup_key(envelope)

    async def process_one(self) -> bool:
        """Process a single relay message.

        Returns:
            True when a message was handled, False on poll timeout.
        """
        message = await self._relay.receive(timeout_seconds=self._config.poll_timeout_seconds)
        if message is None:
            return False
        self._metric("received")
        prepared = await self._prepare(message)
        if prepared is None:
            return True
        envelope, key = prepared

        if key and key in self._dedup:
            await self._relay.publish_result(dict(self._dedup[key]))
            await self._relay.ack(message.message_id)
            self._metric("acked")
            logger.info("duplicate delivery suppressed", dedup_key="***")
            return True

        started = time.monotonic()
        try:
            result = await self._dispatcher.dispatch(envelope)
        except Exception as exc:  # noqa: BLE001 - classification decides the path.
            await self._handle_dispatch_error(message, envelope, exc)
            return True

        latency = time.monotonic() - started
        redacted = redact_mapping(result)
        if key:
            self._dedup[key] = redacted
        await self._observe_success(envelope, latency, str(result.get("state", "UNKNOWN")))
        await self._relay.publish_result(redacted)
        await self._relay.ack(message.message_id)
        self._metric("acked")
        logger.info("message processed", capability=envelope.get("capability"), state=result.get("state"))
        return True

    async def run(self) -> None:
        """Run the poll loop until stop() is called (graceful: finishes in-flight)."""
        logger.info("worker started")
        while not self._stop.is_set():
            try:
                await self.process_one()
            except Exception as exc:  # noqa: BLE001 - the loop must survive transport faults.
                logger.error("worker loop fault", error=type(exc).__name__)
                await asyncio.sleep(0.5)
        logger.info("worker stopped")


async def run_worker_forever(
    relay: RelayTransport | None = None,
    dispatcher: CommandDispatcher | None = None,
    config: WorkerConfig | None = None,
) -> None:
    """Convenience runner with an in-memory relay (lab/tests entry wiring)."""
    relay = relay or InMemoryRelay()
    if dispatcher is None:
        raise ValueError("A dispatcher is required to run the worker.")
    await OutboundWorker(relay, dispatcher, config).run()
