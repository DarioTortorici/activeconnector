"""Structured JSON logging with mandatory redaction of sensitive values.

Log record fields: timestamp, ticket, component, severity, result, correlation.
Secrets (passwords, tokens, nonces, private keys) are replaced before emission
and must never reach logs, audit, traces, exceptions or API responses.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Mapping
from contextvars import ContextVar
from typing import Any

import structlog

correlation_id_ctx: ContextVar[str | None] = ContextVar("mwa_correlation_id", default=None)
ticket_id_ctx: ContextVar[str | None] = ContextVar("mwa_ticket_id", default=None)

REDACTED_PLACEHOLDER = "***REDACTED***"

# Case-insensitive key fragments whose values must never be logged.
REDACTED_KEY_FRAGMENTS: frozenset[str] = frozenset(
    {
        "password",
        "unicodepwd",
        "passwd",
        "pwd",
        "secret",
        "token",
        "nonce",
        "private_key",
        "certificate_private",
        "authorization",
        "cookie",
        "sessionkey",
        "kerberos_ticket",
    }
)


def _is_sensitive_key(key: str) -> bool:
    """Return True when a mapping key looks like it holds a secret."""
    lowered = key.lower().replace("-", "_").replace(" ", "_")
    return any(fragment in lowered for fragment in REDACTED_KEY_FRAGMENTS)


def redact_value(key: str, value: Any) -> Any:
    """Redact a single value when its key is sensitive.

    Args:
        key: Mapping key associated with the value.
        value: Value to inspect.

    Returns:
        Placeholder when sensitive, otherwise the original value.
    """
    if _is_sensitive_key(key):
        return REDACTED_PLACEHOLDER
    if isinstance(value, str) and len(value) > 0 and key.lower() in {"new_rdn", "display_name"}:
        return value
    return value


def redact_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of a mapping with sensitive values redacted (one level deep, recursive).

    Args:
        data: Mapping that may contain secrets (request bodies, envelopes, evidence).

    Returns:
        Redacted plain dict safe for logging.
    """
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if _is_sensitive_key(str(key)):
            redacted[key] = REDACTED_PLACEHOLDER
        elif isinstance(value, Mapping):
            redacted[key] = redact_mapping(value)
        elif isinstance(value, list):
            redacted[key] = [redact_mapping(v) if isinstance(v, Mapping) else v for v in value]
        else:
            redacted[key] = value
    return redacted


def _redact_event_dict(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor applying redaction to every emitted event."""
    return redact_mapping(event_dict)


def _inject_context(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor injecting correlation/ticket ids from contextvars."""
    correlation = correlation_id_ctx.get()
    ticket = ticket_id_ctx.get()
    if correlation is not None:
        event_dict.setdefault("correlation_id", correlation)
    if ticket is not None:
        event_dict.setdefault("ticket_id", ticket)
    return event_dict


_configured_state: dict[str, bool] = {"done": False}


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Configure structlog once for the whole process.

    Args:
        level: Root log level name (e.g. "INFO").
        json_output: When True emit JSON lines, otherwise human-readable console.
    """
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(level=numeric, stream=sys.stdout, force=True)

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        _inject_context,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
        _redact_event_dict,
        structlog.processors.StackInfoRenderer(),
    ]
    processors.append(structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(numeric),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    _configured_state["done"] = True


def get_logger(component: str) -> Any:
    """Return a bound logger for a component (auto-configures defaults once).

    Args:
        component: Stable component name (e.g. "api", "worker", "ldap").

    Returns:
        structlog bound logger with component pre-bound.
    """
    if not _configured_state["done"]:
        configure_logging()
    return structlog.get_logger(component=component)


def set_log_context(*, correlation_id: str | None = None, ticket_id: str | None = None) -> None:
    """Bind correlation/ticket ids for the current async context.

    Args:
        correlation_id: Value of X-Correlation-ID for this request/message.
        ticket_id: Ticket id associated with this request/message, if any.
    """
    if correlation_id is not None:
        correlation_id_ctx.set(correlation_id)
    if ticket_id is not None:
        ticket_id_ctx.set(ticket_id)
