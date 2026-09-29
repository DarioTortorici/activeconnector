"""Group routes: CRUD plus membership add/remove."""

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
from mwa_ad_connector.api.schemas.groups import (
    CreateGroupRequest,
    DeleteGroupRequest,
    MemberAddRequest,
    MemberRemoveRequest,
    MoveGroupRequest,
    RenameGroupRequest,
    UpdateGroupAttributesRequest,
)

router = APIRouter(tags=["groups"])

_MemberWriteScope = Depends(require_scopes("ad.group.member.write"))
_GroupCreateScope = Depends(require_scopes("ad.group.create"))
_GroupAttrsScope = Depends(require_scopes("ad.group.attributes.write"))
_GroupRenameScope = Depends(require_scopes("ad.group.rename"))
_GroupMoveScope = Depends(require_scopes("ad.group.move"))
_GroupDeleteScope = Depends(require_scopes("ad.group.delete"))


def _target(group_guid: str) -> dict[str, str]:
    """Build the canonical group target reference for mutations."""
    return {"object_type": "GROUP", "object_guid": group_guid}


@router.post("/groups/{group_guid}/members:add", response_model=OperationStatusResponse)
async def add_member(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    group_guid: str,
    body: MemberAddRequest,
    *,
    caller: Any = _MemberWriteScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Add one member (idempotent: present member is NO_OP, verified same-DC)."""
    result = await execute_capability(
        operation_service,
        capability="group.member.add",
        target=_target(group_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/groups/{group_guid}/members:remove", response_model=OperationStatusResponse)
async def remove_member(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    group_guid: str,
    body: MemberRemoveRequest,
    *,
    caller: Any = _MemberWriteScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Remove one member (idempotent: absent member is NO_OP)."""
    result = await execute_capability(
        operation_service,
        capability="group.member.remove",
        target=_target(group_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/groups", response_model=OperationStatusResponse)
async def create_group(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    body: CreateGroupRequest,
    *,
    caller: Any = _GroupCreateScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Create a group inside a managed parent OU."""
    result = await execute_capability(
        operation_service,
        capability="group.create",
        target={"object_type": "GROUP"},
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/groups/{group_guid}:update-attributes", response_model=OperationStatusResponse)
async def update_group_attributes(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    group_guid: str,
    body: UpdateGroupAttributesRequest,
    *,
    caller: Any = _GroupAttrsScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Update allowlisted group attributes via staged diff."""
    result = await execute_capability(
        operation_service,
        capability="group.attributes.update",
        target=_target(group_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/groups/{group_guid}:rename", response_model=OperationStatusResponse)
async def rename_group(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    group_guid: str,
    body: RenameGroupRequest,
    *,
    caller: Any = _GroupRenameScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Rename a group (objectGUID invariant, verified read-after-write)."""
    result = await execute_capability(
        operation_service,
        capability="group.rename",
        target=_target(group_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/groups/{group_guid}:move", response_model=OperationStatusResponse)
async def move_group(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    group_guid: str,
    body: MoveGroupRequest,
    *,
    caller: Any = _GroupMoveScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Move a group between managed OUs."""
    result = await execute_capability(
        operation_service,
        capability="group.move",
        target=_target(group_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.delete("/groups/{group_guid}", response_model=OperationStatusResponse)
async def delete_group(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    group_guid: str,
    body: DeleteGroupRequest,
    *,
    caller: Any = _GroupDeleteScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Delete a group (non-privileged, membership policy enforced server-side)."""
    result = await execute_capability(
        operation_service,
        capability="group.delete",
        target=_target(group_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)
