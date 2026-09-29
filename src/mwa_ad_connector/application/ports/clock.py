"""Clock port (deterministic time source for tests)."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """Abstract clock returning timezone-aware timestamps."""

    def now(self) -> datetime:
        """Return the current timezone-aware UTC timestamp.

        Returns:
            Aware datetime in UTC.
        """
        ...

    def monotonic(self) -> float:
        """Return a monotonic timestamp for timeouts/backoff.

        Returns:
            Seconds as float from an arbitrary origin.
        """
        ...
