"""Relay abstraction: swappable outbound transport (in-memory default, Service Bus stub).

The core (worker, services) depends only on RelayTransport; concrete SDKs stay
behind this boundary so at-least-once receive, dedup and result publishing are
transport-agnostic.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol


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
    """Azure Service Bus relay stub with the same interface (cloud-integration step).

    Raises TransportError on use until connection details and the SDK wiring land;
    exists so call sites depend on the interface, never on the SDK.
    """

    def __init__(self, *, fully_qualified_namespace: str = "", queue_name: str = "") -> None:
        """Record (but do not connect to) the Service Bus endpoint.

        Args:
            fully_qualified_namespace: Service Bus namespace host.
            queue_name: Queue holding command envelopes.
        """
        self.fully_qualified_namespace = fully_qualified_namespace
        self.queue_name = queue_name

    def _unavailable(self) -> TransportError:
        """Build the not-yet-wired error (no SDK import at module load)."""
        return TransportError(
            "ServiceBusRelay is not wired in this build; configure the cloud-integration "
            "transport or use InMemoryRelay for lab/tests."
        )

    async def receive(self, timeout_seconds: float = 1.0) -> RelayMessage | None:
        """Not wired: raise TransportError (same signature as the interface)."""
        _ = timeout_seconds
        raise self._unavailable()

    async def ack(self, message_id: str) -> None:
        """Not wired: raise TransportError (same signature as the interface)."""
        _ = message_id
        raise self._unavailable()

    async def abandon(self, message_id: str) -> None:
        """Not wired: raise TransportError (same signature as the interface)."""
        _ = message_id
        raise self._unavailable()

    async def publish_result(self, result: dict[str, Any]) -> None:
        """Not wired: raise TransportError (same signature as the interface)."""
        _ = result
        raise self._unavailable()

    async def publish(self, envelope: dict[str, Any]) -> str:
        """Not wired: raise TransportError (same signature as the interface)."""
        _ = envelope
        raise self._unavailable()
