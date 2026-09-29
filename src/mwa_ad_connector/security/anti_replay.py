"""Anti-replay: timestamp skew plus single-use nonces with TTL (Step 8)."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol

from mwa_ad_connector.security.jwt_validation import AuthenticationFailed

_MAX_NONCE_LENGTH = 256


class ReplayDetected(Exception):
    """Raised when a nonce is reused inside its TTL window."""

    def __init__(self, reason: str = "request nonce was already used") -> None:
        super().__init__(reason)
        self.code = "REPLAY_DETECTED"


class StaleTimestamp(AuthenticationFailed):
    """Raised when the request timestamp is outside the allowed skew window."""

    def __init__(self, reason: str = "request timestamp is outside the allowed skew") -> None:
        super().__init__(reason)


class NonceStore(Protocol):
    """Port for single-use nonce tracking (mirror of ``application.ports.nonce_store``)."""

    def claim(self, nonce: str, expires_at: float) -> bool:
        """Atomically claim ``nonce``; True when newly claimed, False when seen."""
        ...  # pragma: no cover

    def purge_expired(self, now: float) -> int:
        """Delete expired nonce entries; return the removed count."""
        ...  # pragma: no cover


def _as_epoch(value: datetime | float | int) -> float:
    if isinstance(value, datetime):
        aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return aware.timestamp()
    return float(value)


class AntiReplayService:
    """Enforce request freshness and nonce single-use."""

    def __init__(
        self,
        store: NonceStore,
        *,
        max_skew_seconds: int = 300,
        nonce_ttl_seconds: int = 600,
    ) -> None:
        """Bind the service to a nonce store and window configuration."""
        if max_skew_seconds <= 0 or nonce_ttl_seconds <= 0:
            raise ValueError("skew and TTL windows must be positive")
        self._store = store
        self._max_skew = float(max_skew_seconds)
        self._ttl = float(nonce_ttl_seconds)

    @property
    def max_skew_seconds(self) -> float:
        """Return the configured timestamp skew tolerance."""
        return self._max_skew

    @property
    def nonce_ttl_seconds(self) -> float:
        """Return the configured nonce TTL."""
        return self._ttl

    def check(
        self,
        *,
        timestamp: datetime | float | int,
        nonce: str,
        now: float | None = None,
    ) -> None:
        """Validate freshness and claim the nonce (fail-closed).

        Raises:
            AuthenticationFailed: On empty/oversized nonce.
            StaleTimestamp: When the timestamp is outside the skew window.
            ReplayDetected: When the nonce was already claimed.
        """
        current = time.time() if now is None else float(now)
        if not nonce or not nonce.strip() or len(nonce) > _MAX_NONCE_LENGTH:
            raise AuthenticationFailed("request nonce is missing or malformed")
        if abs(current - _as_epoch(timestamp)) > self._max_skew:
            raise StaleTimestamp(f"timestamp skew exceeds {self._max_skew:.0f}s tolerance")
        self._store.purge_expired(current)
        if not self._store.claim(nonce.strip(), current + self._ttl):
            raise ReplayDetected
