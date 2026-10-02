"""Relay abstraction: swappable outbound transport (in-memory default, Service Bus).

The core (worker, services) depends only on RelayTransport; concrete SDKs stay
behind this boundary so at-least-once receive, dedup and result publishing are
transport-agnostic. The Service Bus adapter imports the SDK lazily inside its
methods, so the module stays importable without credentials or the package.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Callable
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass, field
from typing import Any, Protocol

from mwa_ad_connector.infrastructure.telemetry.logging import get_logger

logger = get_logger("servicebus-relay")


class TransportError(Exception):
    """Transport-level failure (outage, malformed message, missing relay)."""


@dataclass
class RelayMessage:
    """One command envelope delivered by the relay (at-least-once)."""

    message_id: str
    envelope: dict[str, Any]
    enqueued_at: float = field(default_factory=time.time)
    delivery_count: int = 1

    @classmethod
    def new(cls, envelope: dict[str, Any]) -> RelayMessage:
        """Wrap an envelope in a fresh relay message with a unique id."""
        return cls(message_id=f"msg-{uuid.uuid4().hex}", envelope=dict(envelope))


class RelayTransport(Protocol):
    """Minimal outbound-compatible relay surface (receive/ack/publish)."""

    async def receive(self, timeout_seconds: float = 1.0) -> RelayMessage | None:
        """Receive one message (None on timeout); caller must ack/abandon."""
        ...  # pragma: no cover

    async def ack(self, message_id: str) -> None:
        """Acknowledge successful handling (at-least-once: ack only when done)."""
        ...  # pragma: no cover

    async def abandon(self, message_id: str) -> None:
        """Release a message for redelivery (transient failure path)."""
        ...  # pragma: no cover

    async def publish_result(self, result: dict[str, Any]) -> None:
        """Publish a redacted operation result for the cloud consumer."""
        ...  # pragma: no cover

    async def publish(self, envelope: dict[str, Any]) -> str:
        """Enqueue an envelope (tests/lab injection); returns the message id."""
        ...  # pragma: no cover


class InMemoryRelay:
    """In-process relay for tests, lab and single-host deployments."""

    def __init__(self) -> None:
        """Create empty queues and result/pending stores."""
        self._queue: asyncio.Queue[RelayMessage] = asyncio.Queue()
        self._pending: dict[str, RelayMessage] = {}
        self.results: list[dict[str, Any]] = []
        self.acked: list[str] = []
        self.abandoned: list[str] = []

    async def publish(self, envelope: dict[str, Any]) -> str:
        """Enqueue an envelope; returns the assigned message id."""
        message = RelayMessage.new(envelope)
        await self._queue.put(message)
        return message.message_id

    async def receive(self, timeout_seconds: float = 1.0) -> RelayMessage | None:
        """Dequeue one message with timeout; tracks it as pending until ack."""
        try:
            message = await asyncio.wait_for(self._queue.get(), timeout=timeout_seconds)
        except TimeoutError:
            return None
        self._pending[message.message_id] = message
        return message

    async def ack(self, message_id: str) -> None:
        """Mark a pending message handled."""
        self._pending.pop(message_id, None)
        self.acked.append(message_id)

    async def abandon(self, message_id: str) -> None:
        """Requeue a pending message with an incremented delivery count."""
        message = self._pending.pop(message_id, None)
        if message is not None:
            message.delivery_count += 1
            await self._queue.put(message)
        self.abandoned.append(message_id)

    async def publish_result(self, result: dict[str, Any]) -> None:
        """Append a redacted result for the cloud consumer."""
        self.results.append(dict(result))

    @property
    def pending_count(self) -> int:
        """Number of messages received but not yet acked/abandoned."""
        return len(self._pending)

    @property
    def queued_count(self) -> int:
        """Number of messages waiting for delivery."""
        return self._queue.qsize()


class ServiceBusRelay:
    """Azure Service Bus adapter implementing RelayTransport (lazy SDK import).

    The SDK client/receiver/senders are created on first use and reused; the
    SDK stays behind the client_factory seam so tests inject fakes and never
    touch the network. Empty configuration fails closed with TransportError.
    """

    def __init__(
        self,
        connection_string: str = "",
        command_queue: str = "",
        result_queue: str = "",
        *,
        client_factory: Callable[[], Any] | None = None,
        fully_qualified_namespace: str = "",
        queue_name: str = "",
    ) -> None:
        """Record the Service Bus endpoint and queue names (no connection yet).

        Args:
            connection_string: Service Bus connection string (secret).
            command_queue: Queue carrying inbound command envelopes.
            result_queue: Queue carrying outbound operation results.
            client_factory: Optional zero-arg factory returning an async client
                (tests/lab); when omitted the SDK client is built lazily.
            fully_qualified_namespace: Deprecated alias; ignored (legacy call sites).
            queue_name: Deprecated alias for command_queue (legacy call sites).
        """
        self.connection_string = connection_string
        self.command_queue = command_queue or queue_name
        self.result_queue = result_queue or self.command_queue
        self.fully_qualified_namespace = fully_qualified_namespace
        self.queue_name = queue_name
        self._client_factory = client_factory
        self._client: Any = None
        self._receiver: Any = None
        self._senders: dict[str, Any] = {}
        self._pending: dict[str, tuple[Any, Any]] = {}
        self._stack: AsyncExitStack = AsyncExitStack()

    def _require_config(self) -> None:
        """Fail closed when no connection string was configured."""
        if not self.connection_string:
            raise TransportError("Service Bus relay is not configured; refusing to use it (fail-closed).")

    def _get_client(self) -> Any:
        """Return the cached async client, creating it lazily on first use."""
        self._require_config()
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                from azure.servicebus.aio import ServiceBusClient  # noqa: PLC0415 - lazy SDK import.

                self._client = ServiceBusClient.from_connection_string(self.connection_string)
        return self._client

    async def _get_receiver(self) -> Any:
        """Open (once) and return the command-queue receiver."""
        if self._receiver is None:
            candidate = self._get_client().get_queue_receiver(queue_name=self.command_queue)
            self._receiver = await self._stack.enter_async_context(candidate)
        return self._receiver

    async def _get_sender(self, queue_name: str) -> Any:
        """Open (once per queue) and return the sender for a queue."""
        sender = self._senders.get(queue_name)
        if sender is None:
            candidate = self._get_client().get_queue_sender(queue_name=queue_name)
            sender = await self._stack.enter_async_context(candidate)
            self._senders[queue_name] = sender
        return sender

    @staticmethod
    def _build_message(body: dict[str, Any], *, correlation_id: Any = None) -> Any:
        """Build an SDK message carrying the JSON body and an optional correlation id."""
        from azure.servicebus import ServiceBusMessage  # noqa: PLC0415 - lazy SDK import.

        candidate = body.get("message_id")
        message_id = str(candidate) if candidate else f"msg-{uuid.uuid4().hex}"
        correlation = str(correlation_id) if correlation_id else None
        return ServiceBusMessage(json.dumps(body), message_id=message_id, correlation_id=correlation)

    async def _dead_letter_malformed(self, receiver: Any, message: Any) -> None:
        """Best-effort dead-letter a malformed envelope so it cannot poison the queue."""
        try:
            await receiver.dead_letter_message(message, reason="MALFORMED_ENVELOPE")
        except Exception as exc:  # noqa: BLE001 - best effort; never break the receive loop.
            logger.warning("service bus dead-letter failed", error=type(exc).__name__)

    async def receive(self, timeout_seconds: float = 1.0) -> RelayMessage | None:
        """Receive one command message, decoding its JSON body (None on timeout)."""
        self._require_config()
        try:
            receiver = await self._get_receiver()
            messages = await receiver.receive_messages(max_message_count=1, max_wait_time=timeout_seconds)
            if not messages:
                return None
            message = messages[0]
            try:
                decoded = json.loads(str(message))
            except ValueError:
                decoded = None
            if not isinstance(decoded, dict):
                await self._dead_letter_malformed(receiver, message)
                return None
            message_id = str(message.message_id) if message.message_id else f"msg-{uuid.uuid4().hex}"
            self._pending[message_id] = (receiver, message)
            return RelayMessage(
                message_id=message_id,
                envelope=decoded,
                delivery_count=message.delivery_count or 1,
            )
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001 - SDK faults map to a generic transport error.
            logger.warning("service bus receive failed", error=type(exc).__name__)
            raise TransportError("Service Bus receive failed.") from None

    async def ack(self, message_id: str) -> None:
        """Complete the pending message (at-least-once: only after success)."""
        self._require_config()
        entry = self._pending.get(message_id)
        if entry is None:
            logger.debug("service bus ack for unknown message", message_id=message_id)
            return
        receiver, message = entry
        try:
            await receiver.complete_message(message)
        except Exception as exc:  # noqa: BLE001 - SDK faults map to a generic transport error.
            logger.warning("service bus ack failed", error=type(exc).__name__)
            raise TransportError("Service Bus acknowledge failed.") from None
        finally:
            self._pending.pop(message_id, None)

    async def abandon(self, message_id: str) -> None:
        """Release the pending message for redelivery (transient failure path)."""
        self._require_config()
        entry = self._pending.get(message_id)
        if entry is None:
            logger.debug("service bus abandon for unknown message", message_id=message_id)
            return
        receiver, message = entry
        try:
            await receiver.abandon_message(message)
        except Exception as exc:  # noqa: BLE001 - SDK faults map to a generic transport error.
            logger.warning("service bus abandon failed", error=type(exc).__name__)
            raise TransportError("Service Bus abandon failed.") from None
        finally:
            self._pending.pop(message_id, None)

    async def publish_result(self, result: dict[str, Any]) -> None:
        """Publish a redacted result on the result queue, carrying correlation."""
        self._require_config()
        try:
            sender = await self._get_sender(self.result_queue)
            await sender.send_messages(self._build_message(result, correlation_id=result.get("correlation_id")))
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001 - SDK faults map to a generic transport error.
            logger.warning("service bus publish_result failed", error=type(exc).__name__)
            raise TransportError("Service Bus result publish failed.") from None

    async def publish(self, envelope: dict[str, Any]) -> str:
        """Publish an envelope on the command queue; returns the assigned id."""
        self._require_config()
        try:
            sender = await self._get_sender(self.command_queue)
            message = self._build_message(envelope, correlation_id=envelope.get("correlation_id"))
            await sender.send_messages(message)
            return str(message.message_id)
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001 - SDK faults map to a generic transport error.
            logger.warning("service bus publish failed", error=type(exc).__name__)
            raise TransportError("Service Bus publish failed.") from None

    async def close(self) -> None:
        """Close receivers, senders and the underlying client if created."""
        # Clearing pending here intentionally does not settle: unacked messages stay
        # locked until the broker lock expires, preserving at-least-once redelivery.
        self._pending.clear()
        stack = self._stack
        self._stack = AsyncExitStack()
        self._receiver = None
        self._senders = {}
        if stack is not None:  # pragma: no cover - always set by __init__.
            with suppress(Exception):
                await stack.aclose()
        client = self._client
        self._client = None
        if client is not None:
            with suppress(Exception):
                await client.close()
