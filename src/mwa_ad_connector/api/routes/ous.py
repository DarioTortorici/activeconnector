"""Organizational unit routes: create, rename, move, delete (empty-only)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from mwa_ad_connector.api.dependencies import (
    CorrelationIdDep,
    IdempotencyKeyDep,
    OperationServiceDep,
    TicketIdDep,
    require_scopes,
)
from mwa_ad_connector.api.routes import execute_capability, mutation_response
from mwa_ad_connector.api.schemas.common import OperationStatusResponse
from mwa_ad_connector.api.schemas.ous import CreateOuRequest, DeleteOuRequest, MoveOuRequest, RenameOuRequest

router = APIRouter(tags=["ous"])

_OuCreateScope = Depends(require_scopes("ad.ou.create"))
_OuRenameScope = Depends(require_scopes("ad.ou.rename"))
_OuMoveScope = Depends(require_scopes("ad.ou.move"))
_OuDeleteScope = Depends(require_scopes("ad.ou.delete"))


def _target(ou_guid: str) -> dict[str, str]:
    """Build the canonical OU target reference for mutations."""
    return {"object_type": "OU", "object_guid": ou_guid}


@router.post("/ous", response_model=OperationStatusResponse)
async def create_ou(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    body: CreateOuRequest,
    *,
    caller: Any = _OuCreateScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Create a child OU under a managed parent scope."""
    result = await execute_capability(
        operation_service,
        capability="ou.create",
        target={"object_type": "OU"},
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/ous/{ou_guid}:rename", response_model=OperationStatusResponse)
async def rename_ou(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    ou_guid: str,
    body: RenameOuRequest,
    *,
    caller: Any = _OuRenameScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Rename an OU (objectGUID invariant, verified read-after-write)."""
    result = await execute_capability(
        operation_service,
        capability="ou.rename",
        target=_target(ou_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/ous/{ou_guid}:move", response_model=OperationStatusResponse)
async def move_ou(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    ou_guid: str,
    body: MoveOuRequest,
    *,
    caller: Any = _OuMoveScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Move an OU subtree within managed scope (preflight enforced server-side)."""
    result = await execute_capability(
        operation_service,
        capability="ou.move",
        target=_target(ou_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.delete("/ous/{ou_guid}", response_model=OperationStatusResponse)
async def delete_ou(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    ou_guid: str,
    body: DeleteOuRequest,
    *,
    caller: Any = _OuDeleteScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Delete an OU (empty and unprotected only)."""
    result = await execute_capability(
        operation_service,
        capability="ou.delete",
        target=_target(ou_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)
