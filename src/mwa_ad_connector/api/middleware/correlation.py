"""Correlation middleware: propagates X-Correlation-ID end to end (plus traceparent)."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from mwa_ad_connector.infrastructure.telemetry.logging import set_log_context

CORRELATION_HEADER = "X-Correlation-ID"

_current: dict[str, str | None] = {"id": None}


def get_correlation_id() -> str | None:
    """Return the correlation id bound to the current request, if any."""
    return _current["id"]


def _new_correlation_id() -> str:
    """Generate a new random correlation id (UUID4 hex)."""
    return uuid.uuid4().hex


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Ensure every request/response carries a correlation id.

    Reads X-Correlation-ID (or generates one), stores it on request.state,
    binds it to the logging context, and echoes it on the response.
    """

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Attach/propagate the correlation id around the downstream handler."""
        correlation_id = request.headers.get(CORRELATION_HEADER) or _new_correlation_id()
        request.state.correlation_id = correlation_id
        _current["id"] = correlation_id
        set_log_context(correlation_id=correlation_id)
        try:
            response = await call_next(request)
        finally:
            _current["id"] = None
        response.headers[CORRELATION_HEADER] = correlation_id
        return response
