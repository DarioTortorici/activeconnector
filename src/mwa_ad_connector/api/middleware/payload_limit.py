"""Payload size guard: rejects oversized bodies with 413 before routing."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB: capability payloads are small by design.


def payload_too_large_response(limit_bytes: int) -> JSONResponse:
    """Build the stable 413 error body (no request content echoed back).

    Args:
        limit_bytes: Configured maximum accepted body size.

    Returns:
        JSONResponse with code PAYLOAD_TOO_LARGE.
    """
    return JSONResponse(
        status_code=413,
        content={
            "error": {
                "code": "PAYLOAD_TOO_LARGE",
                "category": "VALIDATION",
                "message": f"Request body exceeds the {limit_bytes} byte limit.",
                "retryable": False,
                "remediation": "Reduce payload size (paging, projections) and retry.",
            }
        },
    )


class PayloadLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the configured maximum."""

    def __init__(self, app: object, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        """Create the middleware.

        Args:
            app: Downstream ASGI app.
            max_bytes: Maximum accepted Content-Length in bytes.
        """
        super().__init__(app)  # type: ignore[arg-type]
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Short-circuit with 413 when Content-Length is over budget."""
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > self.max_bytes:
            return payload_too_large_response(self.max_bytes)
        return await call_next(request)
