"""Readiness check collection with fail-closed, redacted details."""

from __future__ import annotations

import asyncio
from typing import Any

from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.config.validation import ConfigurationError, validate_startup


def _check(name: str, healthy: bool, detail: str = "") -> dict[str, Any]:
    """Build one readiness check entry."""
    return {"name": name, "healthy": healthy, "detail": detail[:256]}


def _fault_code(exc: BaseException) -> str:
    """Return a redacted fault label (never raw messages)."""
    code = getattr(exc, "code", None)
    if code:
        return str(code)
    return type(exc).__name__


def _configuration_check(settings: ConnectorSettings) -> dict[str, Any]:
    """Validate startup configuration without leaking paths or DNs."""
    try:
        validate_startup(settings)
    except ConfigurationError:
        return _check("configuration_valid", False, "configuration_invalid")
    except Exception as exc:  # noqa: BLE001 - fail closed on any validation fault.
        return _check("configuration_valid", False, _fault_code(exc))
    return _check("configuration_valid", True, "valid")


async def _operation_store_check(store: Any) -> dict[str, Any]:  # noqa: ANN401 - store duck-typed.
    """Probe the operation store with a bounded read."""
    try:
        await store.list(limit=1)
    except Exception as exc:  # noqa: BLE001 - fail closed on store faults.
        return _check("operation_store", False, _fault_code(exc))
    return _check("operation_store", True, "ok")


async def _audit_store_check(store: Any) -> dict[str, Any]:  # noqa: ANN401 - store duck-typed.
    """Probe the audit store with a bounded export."""
    try:
        await store.export(limit=1)
    except Exception as exc:  # noqa: BLE001 - fail closed on store faults.
        return _check("audit_store", False, _fault_code(exc))
    return _check("audit_store", True, "ok")


async def _ldap_check(gateway: Any, timeout: float) -> dict[str, Any]:  # noqa: ANN401 - gateway duck-typed.
    """Probe LDAP connectivity with a short timeout and redacted detail."""
    ping = getattr(gateway, "ping", None)
    if not callable(ping):
        return _check("ldap_connectivity", False, "gateway_without_ping")
    try:
        payload = await asyncio.wait_for(ping(), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - fail closed on any connectivity fault.
        return _check("ldap_connectivity", False, _fault_code(exc))
    ok = bool(payload.get("ok", False)) if isinstance(payload, dict) else False
    detail = (
        "reachable" if ok else str(payload.get("detail", "unreachable")) if isinstance(payload, dict) else "unreachable"
    )
    return _check("ldap_connectivity", ok, detail)


async def _audit_chain_check(store: Any) -> dict[str, Any]:  # noqa: ANN401 - store duck-typed.
    """Verify the audit hash chain integrity."""
    verify = getattr(store, "verify_chain", None)
    if not callable(verify):
        return _check("audit_chain", False, "chain_unavailable")
    try:
        report = await verify()
    except Exception as exc:  # noqa: BLE001 - fail closed on chain faults.
        return _check("audit_chain", False, _fault_code(exc))
    if bool(getattr(report, "valid", False)):
        return _check("audit_chain", True, f"checked={int(getattr(report, 'checked', 0))}")
    return _check("audit_chain", False, "chain_broken")


async def collect_readiness(  # noqa: PLR0913 - explicit dependency dimensions.
    *,
    settings: ConnectorSettings,
    gateway: Any,  # noqa: ANN401 - gateway duck-typed.
    operation_store: Any,  # noqa: ANN401 - store duck-typed.
    audit_store: Any,  # noqa: ANN401 - store duck-typed.
    timeout: float,
) -> list[dict[str, Any]]:
    """Collect all readiness checks (fail-closed on any error).

    Args:
        settings: Connector settings to validate.
        gateway: Directory gateway exposing ``ping``.
        operation_store: Raw operation store.
        audit_store: Raw audit store.
        timeout: LDAP connectivity probe timeout in seconds.

    Returns:
        Ordered check entries with redacted details.
    """
    return [
        _configuration_check(settings),
        await _operation_store_check(operation_store),
        await _audit_store_check(audit_store),
        _check("transport", True, "in-memory relay (outbound-only)"),
        await _ldap_check(gateway, timeout),
        await _audit_chain_check(audit_store),
    ]
