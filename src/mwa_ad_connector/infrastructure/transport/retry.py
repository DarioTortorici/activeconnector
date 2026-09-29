"""Retry policy: exponential backoff with jitter plus a retry budget.

Only DEPENDENCY/TIMEOUT/RATE_LIMIT categories are retryable; verification
failures and policy denials are terminal and must never be retried blindly.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

RETRYABLE_CATEGORIES: frozenset[str] = frozenset({"DEPENDENCY", "TIMEOUT", "RATE_LIMIT"})
RETRYABLE_CODES: frozenset[str] = frozenset({"LDAP_UNAVAILABLE", "LDAP_TIMEOUT", "RATE_LIMITED"})

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retry configuration (budget enforced separately)."""

    max_attempts: int = 5
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        """Validate policy bounds eagerly (fail-fast on misconfiguration)."""
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.base_delay_seconds <= 0 or self.max_delay_seconds <= 0:
            raise ValueError("delays must be positive")
        if not 0.0 <= self.jitter_ratio <= 1.0:
            raise ValueError("jitter_ratio must be within [0, 1]")


def compute_backoff_delay(policy: RetryPolicy, attempt: int, rng: random.Random | None = None) -> float:
    """Compute the backoff delay before retry number `attempt` (1-based).

    Exponential growth capped at max_delay_seconds, with symmetric proportional
    jitter to avoid thundering herds.

    Args:
        policy: Retry policy bounds.
        attempt: 1-based retry attempt number (attempt=1 is the first retry).
        rng: Random source (injectable for deterministic tests).

    Returns:
        Delay in seconds (>= 0).
    """
    source = rng or random.Random()  # noqa: S311 - jitter only, not cryptographic.
    grown = policy.base_delay_seconds * (2.0 ** max(0, attempt - 1))
    capped = min(grown, policy.max_delay_seconds)
    jitter = capped * policy.jitter_ratio * (source.random() * 2.0 - 1.0)
    return max(0.0, capped + jitter)


def is_retryable_category(category: str | None) -> bool:
    """Return True only for transient dependency-side failure categories."""
    return (category or "") in RETRYABLE_CATEGORIES


def is_retryable_code(code: str | None) -> bool:
    """Return True only for stable domain codes that are safe to retry."""
    return (code or "") in RETRYABLE_CODES


class RetryBudget:
    """Sliding-window retry budget: caps total retries per period (thundering-herd guard)."""

    def __init__(self, max_retries: int = 100, window_seconds: float = 60.0) -> None:
        """Create the budget.

        Args:
            max_retries: Max retries allowed per window.
            window_seconds: Sliding window length in seconds.
        """
        if max_retries < 0 or window_seconds <= 0:
            raise ValueError("Invalid retry budget bounds.")
        self.max_retries = max_retries
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []

    def try_consume(self, now: float | None = None) -> bool:
        """Consume one retry token when the budget allows.

        Args:
            now: Monotonic timestamp (defaults to time.monotonic()).

        Returns:
            True when the retry may proceed, False when the budget is spent.
        """
        moment = now if now is not None else time.monotonic()
        cutoff = moment - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_retries:
            return False
        self._timestamps.append(moment)
        return True


async def run_with_retry(
    func: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    is_retryable: Callable[[Exception], bool],
    budget: RetryBudget | None = None,
    rng: random.Random | None = None,
) -> T:
    """Run an async callable with bounded retries for transient failures.

    Args:
        func: Zero-argument async callable to execute.
        policy: Backoff bounds.
        is_retryable: Predicate deciding whether an exception may be retried.
        budget: Optional shared retry budget (retry denied when spent).
        rng: Random source for jitter (deterministic in tests).

    Returns:
        The callable result.

    Raises:
        Exception: The last exception when attempts/budget are exhausted.
    """
    last_error: Exception | None = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return await func()
        except Exception as exc:  # noqa: BLE001 - predicate decides retryability.
            last_error = exc
            is_last = attempt >= policy.max_attempts
            if is_last or not is_retryable(exc):
                raise
            if budget is not None and not budget.try_consume():
                raise
            await asyncio.sleep(compute_backoff_delay(policy, attempt, rng))
    raise last_error or RuntimeError("run_with_retry exhausted without an error.")


def classify_transport_error(exc: BaseException) -> dict[str, Any]:
    """Classify a worker-side exception into retryable/terminal handling.

    Args:
        exc: Exception raised during message handling.

    Returns:
        Dict with retryable bool and stable reason code.
    """
    code = getattr(exc, "code", None)
    category = getattr(exc, "category", None)
    if isinstance(code, str) and is_retryable_code(code):
        return {"retryable": True, "reason": code}
    if isinstance(category, str) and is_retryable_category(category):
        return {"retryable": True, "reason": category}
    return {"retryable": False, "reason": code if isinstance(code, str) else type(exc).__name__}
