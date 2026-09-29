"""Request-envelope helpers: approval parsing and filter bound parsing."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from mwa_ad_connector.domain.errors import RequestInvalidError


def parse_approval(parameters: Mapping[str, Any]) -> dict[str, Any] | None:
    """Parse and validate the raw approval mapping.

    Args:
        parameters: Capability request parameters.

    Returns:
        Normalized approval values (approval_id, approved_by, approved_at).

    Raises:
        RequestInvalidError: When the approval context is malformed.
    """
    raw = parameters.get("approval")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise RequestInvalidError("approval must be an object")
    approved_at: Any = raw.get("approved_at")
    if isinstance(approved_at, str):
        try:
            approved_at = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RequestInvalidError("approval.approved_at is invalid") from exc
    if not isinstance(approved_at, datetime):
        raise RequestInvalidError("approval.approved_at is required")
    if approved_at.tzinfo is None:
        approved_at = approved_at.replace(tzinfo=UTC)
    approved_by = raw.get("approved_by")
    if not isinstance(approved_by, (list, tuple)) or not approved_by:
        raise RequestInvalidError("approval.approved_by is required")
    approval_id = str(raw.get("approval_id") or "")
    if not approval_id:
        raise RequestInvalidError("approval.approval_id is required")
    return {"approval_id": approval_id, "approved_by": [str(name) for name in approved_by], "approved_at": approved_at}


def parse_bound(value: str, name: str) -> datetime:
    """Parse an ISO-8601 filter bound into an aware datetime.

    Args:
        value: Raw bound value.
        name: Filter name for the error message.

    Returns:
        Timezone-aware datetime.

    Raises:
        RequestInvalidError: When the bound is not valid ISO-8601.
    """
    try:
        bound = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RequestInvalidError(f"invalid filter: {name}") from exc
    return bound if bound.tzinfo is not None else bound.replace(tzinfo=UTC)
