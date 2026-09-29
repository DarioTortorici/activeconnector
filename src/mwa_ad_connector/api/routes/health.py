"""Liveness and readiness probes (Step 17).

GET /health is anonymous and redacted. GET /readiness requires
ad.readiness.read and reports per-component checks (200 ready / 503 not ready).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from mwa_ad_connector.api.dependencies import (
    GatewayDep,
    OperationServiceDep,
    RuntimeConfig,
    SettingsDep,
    require_scopes,
)
from mwa_ad_connector.api.error_handlers import ConnectorError
from mwa_ad_connector.api.schemas.common import ComponentStatus, HealthResponse, ReadinessResponse

router = APIRouter(tags=["health"])

_ReadinessScope = Depends(require_scopes("ad.readiness.read"))


@router.get("/health", response_model=HealthResponse, summary="Anonymous redacted liveness probe")
async def get_health(settings: RuntimeConfig = SettingsDep) -> HealthResponse:
    """Return process liveness without exposing sensitive topology details."""
    return HealthResponse(status="HEALTHY", version=settings.version, connector_id=settings.connector_id)


async def _collect_checks(
    operation_service: Any,
    gateway: Any,
) -> list[ComponentStatus]:
    """Gather readiness checks, degrading gracefully when a port is unwired."""
    checks: list[ComponentStatus] = [ComponentStatus(name="configuration_valid", healthy=True)]
    try:
        readiness = await operation_service.get_readiness()
        for entry in readiness.get("checks", []):
            checks.append(
                ComponentStatus(
                    name=str(entry.get("name", "unknown")),
                    healthy=bool(entry.get("healthy", False)),
                    detail=str(entry.get("detail", ""))[:256],
                )
            )
    except ConnectorError as exc:
        checks.append(ComponentStatus(name="operation_store", healthy=False, detail=exc.code))
        checks.append(ComponentStatus(name="audit_store", healthy=False, detail=exc.code))
        checks.append(ComponentStatus(name="transport", healthy=False, detail=exc.code))
    try:
        ping = await gateway.ping()
        checks.append(
            ComponentStatus(
                name="ldap_connectivity",
                healthy=bool(ping.get("ok", False)),
                detail="reachable" if ping.get("ok") else str(ping.get("detail", "unreachable"))[:256],
            )
        )
    except ConnectorError as exc:
        checks.append(ComponentStatus(name="ldap_connectivity", healthy=False, detail=exc.code))
    return checks


@router.get("/readiness", summary="Readiness probe (200 ready, 503 not ready)")
async def get_readiness(
    *,
    caller: Any = _ReadinessScope,  # noqa: ANN401, ARG001
    settings: RuntimeConfig = SettingsDep,  # noqa: ARG001
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    gateway: Any = GatewayDep,  # noqa: ANN401
) -> JSONResponse:
    """Report whether the connector is safe to operate (fail-closed on unknowns)."""
    checks = await _collect_checks(operation_service, gateway)
    ready = all(check.healthy for check in checks)
    body = ReadinessResponse(ready=ready, version=settings.version, checks=checks).model_dump(mode="json")
    return JSONResponse(status_code=200 if ready else 503, content=body)
