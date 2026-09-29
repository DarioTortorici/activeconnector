"""Nonce store port (anti-replay backing store)."""

from __future__ import annotations

from typing import Protocol


class NonceStore(Protocol):
    """Abstract single-use nonce registry with TTL semantics."""

    async def check_and_reserve(self, nonce: str, ttl_seconds: int) -> bool:
        """Reserve a nonce or reject it as a replay.

        Args:
            nonce: Single-use value from the envelope/header.
            ttl_seconds: Reservation lifetime in seconds.

        Returns:
            True when newly reserved; False when already seen.
        """
        ...

    async def purge_expired(self) -> int:
        """Remove expired nonce reservations.

        Returns:
            Number of entries removed.
        """
        ...
