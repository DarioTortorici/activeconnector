"""Discovery/read routes: RootDSE, capabilities, resolve, get, search, members."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from mwa_ad_connector.api.dependencies import (
    CorrelationIdDep,
    OperationServiceDep,
    RuntimeConfig,
    SettingsDep,
    require_scopes,
)
from mwa_ad_connector.api.error_handlers import ConnectorError
from mwa_ad_connector.api.routes import execute_capability
from mwa_ad_connector.api.schemas.common import create_page_token, verify_page_token
from mwa_ad_connector.api.schemas.discovery import (
    CapabilitiesResponse,
    DirectoryObjectResponse,
    MembersResponse,
    ResolveRequest,
    ResolveResponse,
    RootDseResponse,
    SearchRequest,
    SearchResponse,
)

router = APIRouter(tags=["discovery"])

_DiscoveryScope = Depends(require_scopes("ad.discovery.read"))
_UserReadScope = Depends(require_scopes("ad.user.read"))
_GroupReadScope = Depends(require_scopes("ad.group.read"))
_MembersReadScope = Depends(require_scopes("ad.group.members.read"))


@router.get("/domains/{domain_id}/rootdse", response_model=RootDseResponse)
async def get_rootdse(
    domain_id: str,
    *,
    caller: Any = _DiscoveryScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """Read the redacted RootDSE view for one configured domain."""
    return await execute_capability(
        operation_service,
        capability="directory.rootdse.read",
        target={"domain_id": domain_id},
        caller=caller,
        idempotency_key=None,
        correlation_id=correlation_id,
        expect_operation=False,
    )


@router.get("/domains/{domain_id}/capabilities", response_model=CapabilitiesResponse)
async def get_capabilities(
    domain_id: str,
    *,
    caller: Any = _DiscoveryScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """List allowlisted capability ids supported for one domain."""
    return await execute_capability(
        operation_service,
        capability="directory.capabilities.read",
        target={"domain_id": domain_id},
        caller=caller,
        idempotency_key=None,
        correlation_id=correlation_id,
        expect_operation=False,
    )


@router.post("/users:resolve", response_model=ResolveResponse)
async def resolve_user(
    body: ResolveRequest,
    *,
    caller: Any = _UserReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """Resolve exactly one user by GUID or allowlisted identifier."""
    return await execute_capability(
        operation_service,
        capability="user.resolve",
        target=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=None,
        correlation_id=correlation_id,
        expect_operation=False,
    )


@router.post("/groups:resolve", response_model=ResolveResponse)
async def resolve_group(
    body: ResolveRequest,
    *,
    caller: Any = _GroupReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """Resolve exactly one group by GUID or allowlisted identifier."""
    return await execute_capability(
        operation_service,
        capability="group.resolve",
        target=body.model_dump(mode="json"),
        caller=caller,
        idempotency_key=None,
        correlation_id=correlation_id,
        expect_operation=False,
    )


@router.get("/users/{object_guid}", response_model=DirectoryObjectResponse)
async def get_user(
    object_guid: str,
    projection: str | None = Query(default=None, max_length=1024),
    *,
    caller: Any = _UserReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """Read one user by objectGUID with an allowlisted projection."""
    fields = [p.strip() for p in (projection or "").split(",") if p.strip()][:64]
    return await execute_capability(
        operation_service,
        capability="user.get",
        target={"object_type": "USER", "object_guid": object_guid},
        parameters={"projection": fields},
        caller=caller,
        idempotency_key=None,
        correlation_id=correlation_id,
        expect_operation=False,
    )


@router.get("/groups/{object_guid}", response_model=DirectoryObjectResponse)
async def get_group(
    object_guid: str,
    projection: str | None = Query(default=None, max_length=1024),
    *,
    caller: Any = _GroupReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """Read one group by objectGUID with an allowlisted projection."""
    fields = [p.strip() for p in (projection or "").split(",") if p.strip()][:64]
    return await execute_capability(
        operation_service,
        capability="group.get",
        target={"object_type": "GROUP", "object_guid": object_guid},
        parameters={"projection": fields},
        caller=caller,
        idempotency_key=None,
        correlation_id=correlation_id,
        expect_operation=False,
    )


def _decode_page_token(token: str | None, settings: RuntimeConfig) -> dict[str, Any]:
    """Verify an incoming page token or return an empty cursor for first pages."""
    if not token:
        return {}
    try:
        return verify_page_token(token, settings.page_token_secret)
    except ValueError as exc:
        raise ConnectorError(
            code="REQUEST_INVALID",
            message=f"Invalid page token: {exc.args[0]}.",
            category="VALIDATION",
            http_status=400,
        ) from exc


async def _search(  # noqa: PLR0913 - explicit search dimensions beat an opaque bundle.
    body: SearchRequest,
    capability: str,
    *,
    caller: Any,
    operation_service: Any,
    settings: RuntimeConfig,
    correlation_id: str,
) -> dict[str, Any]:
    """Run a predefined query-profile search with signed paging."""
    cursor = _decode_page_token(body.page_token, settings)
    result = await execute_capability(
        operation_service,
        capability=capability,
        target={"object_type": body.object_type, "domain_id": body.domain_id},
        parameters={
            "query_profile": body.query_profile,
            "parameters": body.parameters,
            "page_size": body.page_size,
            "cursor": cursor,
        },
        caller=caller,
        idempotency_key=None,
        correlation_id=correlation_id,
        expect_operation=False,
    )
    if result.get("next_cursor"):
        result["next_page_token"] = create_page_token(
            dict(result["next_cursor"]),
            settings.page_token_secret,
            ttl_seconds=settings.page_token_ttl_seconds,
        )
    return {"items": result.get("items", []), "next_page_token": result.get("next_page_token")}


@router.post("/users:search", response_model=SearchResponse)
async def search_users(
    body: SearchRequest,
    *,
    caller: Any = _UserReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    settings: RuntimeConfig = SettingsDep,
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """Search users via predefined query profiles (no raw LDAP filters)."""
    return await _search(
        body,
        "user.search",
        caller=caller,
        operation_service=operation_service,
        settings=settings,
        correlation_id=correlation_id,
    )


@router.post("/groups:search", response_model=SearchResponse)
async def search_groups(
    body: SearchRequest,
    *,
    caller: Any = _GroupReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    settings: RuntimeConfig = SettingsDep,
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """Search groups via predefined query profiles (no raw LDAP filters)."""
    return await _search(
        body,
        "group.search",
        caller=caller,
        operation_service=operation_service,
        settings=settings,
        correlation_id=correlation_id,
    )


@router.get("/groups/{object_guid}/members", response_model=MembersResponse)
async def list_members(  # noqa: PLR0913 - explicit FastAPI dependency dimensions.
    object_guid: str,
    page_size: int = Query(default=50, ge=1, le=1000),
    page_token: str | None = Query(default=None, max_length=4096),
    *,
    caller: Any = _MembersReadScope,  # noqa: ANN401
    operation_service: Any = OperationServiceDep,  # noqa: ANN401
    settings: RuntimeConfig = SettingsDep,
    correlation_id: str = CorrelationIdDep,
) -> dict[str, Any]:
    """List group members with signed paging (unresolved refs flagged)."""
    cursor = _decode_page_token(page_token, settings)
    result = await execute_capability(
        operation_service,
        capability="group.members.list",
        target={"object_type": "GROUP", "object_guid": object_guid},
        parameters={"page_size": page_size, "cursor": cursor},
        caller=caller,
        idempotency_key=None,
        correlation_id=correlation_id,
        expect_operation=False,
    )
    if result.get("next_cursor"):
        result["next_page_token"] = create_page_token(
            dict(result["next_cursor"]),
            settings.page_token_secret,
            ttl_seconds=settings.page_token_ttl_seconds,
        )
    return {
        "group_guid": object_guid,
        "members": result.get("members", []),
        "unresolved_count": result.get("unresolved_count", 0),
        "next_page_token": result.get("next_page_token"),
    }
