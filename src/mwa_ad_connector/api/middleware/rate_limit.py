"""In-memory token-bucket rate limiting (per caller/IP) with 429 + Retry-After."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


@dataclass
class TokenBucket:
    """Single-key token bucket (monotonic clock, lazy refill)."""

    capacity: float
    refill_per_second: float
    tokens: float = field(init=False)
    updated_at: float = field(init=False)

    def __post_init__(self) -> None:
        """Initialize the bucket as full."""
        self.tokens = self.capacity
        self.updated_at = time.monotonic()

    def allow(self) -> tuple[bool, float]:
        """Consume one token when available.

        Returns:
            Tuple (allowed, retry_after_seconds). retry_after is 0 when allowed.
        """
        now = time.monotonic()
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated_at = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True, 0.0
        deficit = 1.0 - self.tokens
        retry_after = deficit / self.refill_per_second if self.refill_per_second > 0 else 60.0
        return False, retry_after


class RateLimiter:
    """Registry of per-key token buckets with idle entry eviction."""

    def __init__(self, capacity: int = 100, refill_per_second: float = 10.0, max_keys: int = 10_000) -> None:
        """Create the limiter.

        Args:
            capacity: Burst size per key.
            refill_per_second: Sustained rate per key.
            max_keys: Upper bound of tracked keys (oldest evicted past it).
        """
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.max_keys = max_keys
        self._buckets: dict[str, TokenBucket] = {}

    def check(self, key: str) -> tuple[bool, float]:
        """Check (and consume) one token for a key.

        Args:
            key: Rate-limit key (caller subject, tenant, or client IP).

        Returns:
            Tuple (allowed, retry_after_seconds).
        """
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self.max_keys:
                oldest = min(self._buckets, key=lambda k: self._buckets[k].updated_at)
                del self._buckets[oldest]
            bucket = TokenBucket(capacity=float(self.capacity), refill_per_second=self.refill_per_second)
            self._buckets[key] = bucket
        return bucket.allow()


def _rate_limit_key(request: Request) -> str:
    """Derive a stable rate-limit key preferring authenticated identity over IP."""
    auth = request.headers.get("authorization", "")
    tenant = request.headers.get("x-tenant-id", "")
    if auth:
        return f"token:{hash(auth) & 0xFFFFFFFF:08x}:{tenant}"
    client = request.client.host if request.client else "unknown"
    return f"ip:{client}:{tenant}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce per-key rate limits; anonymous health/readiness stay lightly limited."""

    def __init__(
        self,
        app: object,
        limiter: RateLimiter | None = None,
        exempt_paths: tuple[str, ...] = ("/api/v1/health",),
    ) -> None:
        """Create the middleware.

        Args:
            app: Downstream ASGI app.
            limiter: Shared limiter instance (created when omitted).
            exempt_paths: Paths never rate limited.
        """
        super().__init__(app)  # type: ignore[arg-type]
        self.limiter = limiter or RateLimiter()
        self.exempt_paths = exempt_paths

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Return 429 with Retry-After when the key is over budget."""
        if request.url.path in self.exempt_paths:
            return await call_next(request)
        allowed, retry_after = self.limiter.check(_rate_limit_key(request))
        if not allowed:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(max(1, int(retry_after + 0.5)))},
                content={
                    "error": {
                        "code": "RATE_LIMITED",
                        "category": "RATE_LIMIT",
                        "message": "Rate limit exceeded; retry after the indicated delay.",
                        "retryable": True,
                        "remediation": "Back off and retry; contact operations if persistent.",
                    }
                },
            )
        return await call_next(request)
