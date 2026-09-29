"""Capability routers mounted under /api/v1 plus shared HTTP-semantics helpers.

Helpers are defined before router imports so route modules can safely do
``from mwa_ad_connector.api.routes import execute_capability``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi.responses import JSONResponse

from mwa_ad_connector.api.error_handlers import ConnectorError
from mwa_ad_connector.api.schemas.common import OperationStatusResponse

# States meaning "really queued": 202 with operation_id + status_url (§3.5).
QUEUED_STATES: frozenset[str] = frozenset({"RECEIVED", "AUTHORIZED", "EXECUTING", "QUEUED", "WAITING_ENTRA_SYNC"})


def status_url_for(operation_id: str) -> str:
    """Build the canonical operation status URL for an operation id."""
    return f"/api/v1/operations/{operation_id}"


async def execute_capability(  # noqa: PLR0913 - helper mirrors the service seam explicitly.
    service: Any,
    *,
    capability: str,
    target: Mapping[str, Any] | None = None,
    parameters: Mapping[str, Any] | None = None,
    caller: Any,
    idempotency_key: str | None,
    correlation_id: str,
    ticket_id: str | None = None,
    dry_run: bool = False,
    expect_operation: bool = True,
) -> dict[str, Any]:
    """Execute one capability through the injected operation service.

    Args:
        expect_operation: When True (mutations) require operation_id/state in the
            result; reads return domain objects and skip that check.

    Raises:
        ConnectorError: INTERNAL_ERROR when a mutation result is malformed.
    """
    result = await service.execute_capability(
        capability=capability,
        target=dict(target or {}),
        parameters=dict(parameters or {}),
        caller=caller,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        ticket_id=ticket_id,
        dry_run=dry_run,
    )
    if expect_operation and (not isinstance(result, dict) or not result.get("operation_id") or not result.get("state")):
        raise ConnectorError(
            code="INTERNAL_ERROR",
            message="Operation service returned a malformed result.",
            category="INTERNAL",
            http_status=500,
        )
    if not isinstance(result, dict):
        raise ConnectorError(
            code="INTERNAL_ERROR",
            message="Operation service returned a malformed result.",
            category="INTERNAL",
            http_status=500,
        )
    return result


def mutation_response(result: Mapping[str, Any]) -> JSONResponse:
    """Map an operation result to HTTP semantics (§3.5).

    200 verified/applied, 202 really queued (operation_id + status_url),
    502 FAILED_VERIFICATION with redacted evidence (never a plain pre-commit error).
    """
    operation_id = str(result.get("operation_id"))
    state = str(result.get("state"))
    body = OperationStatusResponse(
        operation_id=operation_id,
        state=state,
        disposition=result.get("disposition"),
        status_url=str(result.get("status_url") or status_url_for(operation_id)),
        target_object_guid=result.get("target_object_guid"),
        changed_fields=[str(f) for f in (result.get("changed_fields") or [])],
        source_dc=result.get("source_dc"),
        verification_evidence=result.get("verification_evidence"),
    ).model_dump(mode="json", exclude_none=False)
    if state == "FAILED_VERIFICATION":
        return JSONResponse(status_code=502, content=body)
    if state in QUEUED_STATES:
        return JSONResponse(status_code=202, content=body)
    return JSONResponse(status_code=200, content=body)


from mwa_ad_connector.api.routes import accounts, discovery, groups, health, operations, ous  # noqa: E402

__all__ = [
    "accounts",
    "discovery",
    "execute_capability",
    "groups",
    "health",
    "mutation_response",
    "operations",
    "ous",
    "status_url_for",
]
