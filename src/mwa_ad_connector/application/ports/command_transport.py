"""Command transport port (substitutable outbound-only bus/relay).

The on-prem worker polls/receives command envelopes without opening
inbound ports. Concrete transports (Service Bus, relay, file poller for
lab) implement this protocol.
"""

from __future__ import annotations

from typing import Protocol

from mwa_ad_connector.domain.operations import CapabilityRequest, MutationResult


class CommandTransport(Protocol):
    """Abstract outbound-compatible command transport."""

    async def receive(self, max_messages: int = 10) -> list[CapabilityRequest]:
        """Receive a batch of validated command envelopes.

        Args:
            max_messages: Maximum envelopes to return.

        Returns:
            Validated capability requests (envelope validation applied).
        """
        ...

    async def acknowledge(self, message_id: str) -> None:
        """Acknowledge successful handling of a transport message.

        Args:
            message_id: Transport message identifier.
        """
        ...

    async def abandon(self, message_id: str, reason: str = "") -> None:
        """Release a message for redelivery after a retryable failure.

        Args:
            message_id: Transport message identifier.
            reason: Redacted reason label.
        """
        ...

    async def dead_letter(self, message_id: str, reason: str) -> None:
        """Move a poison message to the dead-letter queue.

        Args:
            message_id: Transport message identifier.
            reason: Redacted reason label.
        """
        ...

    async def publish_result(self, result: MutationResult) -> None:
        """Publish a redacted operation result upstream.

        Args:
            result: Verified mutation result (no secrets).
        """
        ...
