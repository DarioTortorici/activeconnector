"""Dead-letter queue: poison-message store with redacted payloads."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from mwa_ad_connector.infrastructure.telemetry.logging import redact_mapping


@dataclass
class DeadLetterRecord:
    """One quarantined message (payload redacted at write time)."""

    message_id: str
    reason: str
    attempts: int
    payload_redacted: dict[str, Any]
    capability: str | None = None
    correlation_id: str | None = None
    dead_lettered_at: float = field(default_factory=time.time)


class DeadLetterStore(Protocol):
    """Durable quarantine surface for poison messages."""

    async def put(self, record: DeadLetterRecord) -> None:
        """Persist one dead-letter record."""
        ...  # pragma: no cover

    async def list(self, limit: int = 100) -> list[DeadLetterRecord]:
        """List recent records (newest last), bounded by limit."""
        ...  # pragma: no cover

    async def count(self) -> int:
        """Return the total quarantined count."""
        ...  # pragma: no cover


class InMemoryDeadLetterStore:
    """In-process DLQ (tests/lab); swap for a durable store in production wiring."""

    def __init__(self) -> None:
        """Create the empty store."""
        self._records: list[DeadLetterRecord] = []

    async def put(self, record: DeadLetterRecord) -> None:
        """Append one record."""
        self._records.append(record)

    async def list(self, limit: int = 100) -> list[DeadLetterRecord]:
        """Return up to `limit` recent records."""
        return list(self._records[-max(1, limit) :])

    async def count(self) -> int:
        """Return the quarantined count."""
        return len(self._records)


def is_poison(delivery_count: int, max_attempts: int) -> bool:
    """Return True when a message exhausted its delivery attempts.

    Args:
        delivery_count: Times the relay delivered this message.
        max_attempts: Configured attempts before quarantine.

    Returns:
        True when the message must be dead-lettered instead of retried.
    """
    return delivery_count >= max(1, max_attempts)


def build_record(
    *,
    message_id: str,
    reason: str,
    attempts: int,
    envelope: dict[str, Any],
    correlation_id: str | None = None,
) -> DeadLetterRecord:
    """Build a dead-letter record with the payload redacted.

    Args:
        message_id: Relay message id.
        reason: Stable quarantine reason (e.g. ENVELOPE_INVALID, POISON).
        attempts: Delivery attempts observed.
        envelope: Original envelope (secrets redacted, never stored raw).
        correlation_id: Correlation id when known.

    Returns:
        DeadLetterRecord safe for operators to inspect.
    """
    capability = envelope.get("capability") if isinstance(envelope, dict) else None
    return DeadLetterRecord(
        message_id=message_id,
        reason=reason,
        attempts=attempts,
        payload_redacted=redact_mapping(envelope if isinstance(envelope, dict) else {"raw": type(envelope).__name__}),
        capability=str(capability) if capability else None,
        correlation_id=correlation_id or (envelope.get("correlation_id") if isinstance(envelope, dict) else None),
    )
