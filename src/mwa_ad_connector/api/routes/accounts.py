"""Account routes: unlock, password, enable/disable, attributes, rename, move, CRUD."""

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
from mwa_ad_connector.api.schemas.accounts import (
    DisableAccountRequest,
    EnableAccountRequest,
    ForcePasswordChangeRequest,
    ResetPasswordRequest,
    UnlockAccountRequest,
)
from mwa_ad_connector.api.schemas.common import OperationStatusResponse
from mwa_ad_connector.api.schemas.users import (
    CreateUserRequest,
    DeleteUserRequest,
    MoveUserRequest,
    RenameUserRequest,
    UpdateUserAttributesRequest,
)

router = APIRouter(tags=["accounts"])

_UnlockScope = Depends(require_scopes("ad.account.unlock"))
_PasswordResetScope = Depends(require_scopes("ad.account.password.reset"))
_ForceChangeScope = Depends(require_scopes("ad.account.password.force_change"))
_AccountStateScope = Depends(require_scopes("ad.account.state.write"))
_UserAttrsScope = Depends(require_scopes("ad.user.attributes.write"))
_UserLifecycleScope = Depends(require_scopes("ad.user.lifecycle.write"))
_UserCreateScope = Depends(require_scopes("ad.user.create"))
_UserDeleteScope = Depends(require_scopes("ad.user.delete"))


def _target(user_guid: str) -> dict[str, str]:
    """Build the canonical user target reference for mutations."""
    return {"object_type": "USER", "object_guid": user_guid}


@router.post("/users/{user_guid}:unlock", response_model=OperationStatusResponse)
async def unlock_account(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: UnlockAccountRequest,
    *,
    caller: Any = _UnlockScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Unlock a locked account (idempotent NO_OP when already unlocked)."""
    result = await execute_capability(
        operation_service,
        capability="account.unlock",
        target=_target(user_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/users/{user_guid}:reset-password", response_model=OperationStatusResponse)
async def reset_password(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: ResetPasswordRequest,
    *,
    caller: Any = _PasswordResetScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Reset a password over a protected channel (secret never logged/returned)."""
    parameters = body.model_dump(mode="json")
    parameters["new_password"] = body.new_password.get_secret_value()
    result = await execute_capability(
        operation_service,
        capability="account.password.reset",
        target=_target(user_guid),
        parameters=parameters,
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/users/{user_guid}:force-password-change", response_model=OperationStatusResponse)
async def force_password_change(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: ForcePasswordChangeRequest,
    *,
    caller: Any = _ForceChangeScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Force password change at next logon (idempotent on state)."""
    result = await execute_capability(
        operation_service,
        capability="account.password.force_change",
        target=_target(user_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/users/{user_guid}:enable", response_model=OperationStatusResponse)
async def enable_account(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: EnableAccountRequest,
    *,
    caller: Any = _AccountStateScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Enable a disabled account (bitwise-safe UAC update, verified)."""
    result = await execute_capability(
        operation_service,
        capability="account.enable",
        target=_target(user_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/users/{user_guid}:disable", response_model=OperationStatusResponse)
async def disable_account(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: DisableAccountRequest,
    *,
    caller: Any = _AccountStateScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Disable an account (protected/service accounts rejected by policy)."""
    result = await execute_capability(
        operation_service,
        capability="account.disable",
        target=_target(user_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/users/{user_guid}:update-attributes", response_model=OperationStatusResponse)
async def update_user_attributes(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: UpdateUserAttributesRequest,
    *,
    caller: Any = _UserAttrsScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Update allowlisted user attributes via staged diff (no generic PATCH)."""
    result = await execute_capability(
        operation_service,
        capability="user.attributes.update",
        target=_target(user_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/users/{user_guid}:rename", response_model=OperationStatusResponse)
async def rename_user(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: RenameUserRequest,
    *,
    caller: Any = _UserLifecycleScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Rename a user (objectGUID invariant, verified read-after-write)."""
    result = await execute_capability(
        operation_service,
        capability="user.rename",
        target=_target(user_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/users/{user_guid}:move", response_model=OperationStatusResponse)
async def move_user(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: MoveUserRequest,
    *,
    caller: Any = _UserLifecycleScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Move a user between managed OUs (both ends in scope)."""
    result = await execute_capability(
        operation_service,
        capability="user.move",
        target=_target(user_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.post("/users", response_model=OperationStatusResponse)
async def create_user(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    body: CreateUserRequest,
    *,
    caller: Any = _UserCreateScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Create a user inside a managed parent OU (naming/schema preflight)."""
    result = await execute_capability(
        operation_service,
        capability="user.create",
        target={"object_type": "USER"},
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)


@router.delete("/users/{user_guid}", response_model=OperationStatusResponse)
async def delete_user(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    user_guid: str,
    body: DeleteUserRequest,
    *,
    caller: Any = _UserDeleteScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    idempotency_key: str = IdempotencyKeyDep,
    ticket_id: str = TicketIdDep,
    correlation_id: str = CorrelationIdDep,
) -> JSONResponse:
    """Delete a user (approval-gated; disable/stage preferred by policy)."""
    result = await execute_capability(
        operation_service,
        capability="user.delete",
        target=_target(user_guid),
        parameters=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=body.dry_run,
    )
    return mutation_response(result)
