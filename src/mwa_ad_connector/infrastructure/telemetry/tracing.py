"""Optional OpenTelemetry tracing helper (no-op safe when SDK is unconfigured)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Literal

try:
    from opentelemetry import trace as _otel_trace
except ImportError:  # pragma: no cover - SDK always present per pyproject, guard for safety.
    _otel_trace = None  # type: ignore[assignment]


def get_tracer(name: str = "mwa-ad-connector") -> Any:
    """Return an OTel tracer, or a no-op tracer when the SDK is unavailable.

    Args:
        name: Instrumentation scope name.

    Returns:
        Tracer-like object with start_as_current_span().
    """
    if _otel_trace is None:  # pragma: no cover
        return _NoopTracer()
    return _otel_trace.get_tracer(name)


class _NoopSpan:
    """No-op span used when tracing is disabled."""

    def set_attribute(self, key: str, value: Any) -> None:
        """Discard span attributes (tracing disabled)."""

    def record_exception(self, exc: BaseException) -> None:
        """Discard exception recording (tracing disabled)."""


class _NoopSpanContext:
    """No-op span context manager."""

    def __init__(self) -> None:
        """Create the no-op span context."""
        self.span = _NoopSpan()

    def __enter__(self) -> _NoopSpan:
        """Enter the no-op span."""
        return self.span

    def __exit__(self, *args: Any) -> Literal[False]:
        """Exit the no-op span without suppressing exceptions."""
        return False


class _NoopTracer:
    """Tracer fallback returning no-op spans."""

    def start_as_current_span(self, name: str, **kwargs: Any) -> _NoopSpanContext:
        """Return a no-op span context (tracing disabled)."""
        return _NoopSpanContext()


@contextmanager
def trace_operation(operation: str, **attributes: Any) -> Iterator[Any]:
    """Trace one connector operation; never logs secrets (attributes must be redacted).

    Args:
        operation: Span name, typically "<capability>" or "http <route>".
        attributes: Redacted scalar span attributes only.

    Yields:
        The active span (real or no-op).
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(operation) as span:
        for key, value in attributes.items():
            if isinstance(value, (str, int, float, bool)):
                span.set_attribute(key, value)
        yield span
