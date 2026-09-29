"""Operation and audit routes: get, allowlisted search, audit retrieval/export."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends

from mwa_ad_connector.api.dependencies import (
    CorrelationIdDep,
    OperationServiceDep,
    RequireCallerDep,
    RuntimeConfig,
    SettingsDep,
    require_scopes,
)
from mwa_ad_connector.api.error_handlers import ConnectorError
from mwa_ad_connector.api.schemas.common import create_page_token, verify_page_token
from mwa_ad_connector.api.schemas.operations import (
    OPERATION_SEARCH_FILTERS,
    AuditExportRequest,
    AuditExportResponse,
    AuditGetResponse,
    OperationGetResponse,
    OperationSearchRequest,
    OperationSearchResponse,
)

router = APIRouter(tags=["operations"])

_OperationReadScope = Depends(require_scopes("ad.operation.read"))
_AuditReadScope = Depends(require_scopes("ad.audit.read"))


@router.get("/operations/{operation_id}", response_model=OperationGetResponse)
async def get_operation(
    operation_id: str,
    *,
    caller: Any = _OperationReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
) -> dict[str, Any]:
    """Fetch one operation with redacted evidence (same tenant/connector only)."""
    record = await operation_service.get_operation(operation_id, caller)
    if record is None:
        raise ConnectorError(
            code="TARGET_NOT_FOUND",
            message=f"Operation {operation_id} not found.",
            category="NOT_FOUND",
            http_status=404,
            operation_id=operation_id,
        )
    return cast("dict[str, Any]", record)


@router.post("/operations:search", response_model=OperationSearchResponse)
async def search_operations(
    body: OperationSearchRequest,
    *,
    caller: Any = _OperationReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    settings: RuntimeConfig = SettingsDep,
    correlation_id: str = CorrelationIdDep,  # noqa: ARG001
) -> dict[str, Any]:
    """Search operations by allowlisted filters with signed paging."""
    unknown = sorted(set(body.filters) - OPERATION_SEARCH_FILTERS)
    if unknown:
        raise ConnectorError(
            code="REQUEST_INVALID",
            message=f"Unsupported operation search filters: {', '.join(unknown)}.",
            category="VALIDATION",
            http_status=400,
        )
    cursor: dict[str, Any] = {}
    if body.page_token:
        try:
            cursor = verify_page_token(body.page_token, settings.page_token_secret)
        except ValueError as exc:
            raise ConnectorError(
                code="REQUEST_INVALID",
                message=f"Invalid page token: {exc.args[0]}.",
                category="VALIDATION",
                http_status=400,
            ) from exc
    result = await operation_service.search_operations(dict(body.filters), body.page_size, cursor or None, caller)
    items = list(result.get("items", []))
    next_token = None
    if result.get("next_cursor"):
        next_token = create_page_token(
            dict(result["next_cursor"]),
            settings.page_token_secret,
            ttl_seconds=settings.page_token_ttl_seconds,
        )
    return {"items": items, "next_page_token": next_token}


@router.get("/audit/{audit_id}", response_model=AuditGetResponse)
async def get_audit(
    audit_id: str,
    *,
    caller: Any = _AuditReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
) -> dict[str, Any]:
    """Fetch one redacted audit record (access itself is audited server-side)."""
    record = await operation_service.get_audit(audit_id, caller)
    if record is None:
        raise ConnectorError(
            code="TARGET_NOT_FOUND",
            message=f"Audit record {audit_id} not found.",
            category="NOT_FOUND",
            http_status=404,
        )
    return cast("dict[str, Any]", record)


@router.post("/audit:export", response_model=AuditExportResponse)
async def export_audit(
    body: AuditExportRequest,
    *,
    caller: Any = RequireCallerDep,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    correlation_id: str = CorrelationIdDep,  # noqa: ARG001
) -> dict[str, Any]:
    """Request a bounded tamper-evident audit export (admin approval enforced)."""
    held = set(getattr(caller, "scopes", None) or [])
    if "ad.audit.export" not in held:
        raise ConnectorError(
            code="CALLER_FORBIDDEN",
            message="Missing required scope: ad.audit.export.",
            category="AUTHORIZATION",
            http_status=403,
            details={"missing_scopes": "ad.audit.export"},
        )
    if body.requested_to <= body.requested_from:
        raise ConnectorError(
            code="REQUEST_INVALID",
            message="requested_to must be after requested_from.",
            category="VALIDATION",
            http_status=400,
        )
    return cast("dict[str, Any]", await operation_service.export_audit(body.model_dump(mode="json"), caller))
