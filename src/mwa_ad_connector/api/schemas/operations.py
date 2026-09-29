"""Operation/audit schemas: get, allowlisted search, audit retrieval/export."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.api.schemas.common import PageTokenRequest

# Allowlisted operation search filters (no free-form search permitted).
OPERATION_SEARCH_FILTERS: frozenset[str] = frozenset(
    {
        "capability",
        "state",
        "ticket_id",
        "target_guid",
        "requested_from",
        "requested_to",
    }
)


class OperationSearchRequest(PageTokenRequest):
    """Search operations by allowlisted filters only (retention applied server-side)."""

    model_config = ConfigDict(extra="forbid")

    filters: dict[str, str] = Field(default_factory=dict, max_length=8)


class OperationSearchResponse(BaseModel):
    """Paged operation list with signed continuation token."""

    model_config = ConfigDict(extra="forbid")

    items: list[dict[str, Any]] = Field(default_factory=list)
    next_page_token: str | None = Field(default=None, max_length=4096)


class OperationGetResponse(BaseModel):
    """Single operation with redacted evidence (same tenant/connector enforced)."""

    model_config = ConfigDict(extra="forbid")

    operation_id: str = Field(min_length=1, max_length=128)
    state: str = Field(min_length=1, max_length=32)
    capability: str | None = Field(default=None, max_length=128)
    disposition: str | None = Field(default=None, max_length=32)
    target_object_guid: str | None = Field(default=None, max_length=64)
    verification_evidence: dict[str, Any] | None = None
    error_code: str | None = Field(default=None, max_length=64)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AuditGetResponse(BaseModel):
    """Single redacted audit record (access itself is audited server-side)."""

    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(min_length=1, max_length=128)
    operation_id: str | None = Field(default=None, max_length=128)
    entries: list[dict[str, Any]] = Field(default_factory=list)
    chain_reference: str | None = Field(default=None, max_length=256)


class AuditExportRequest(BaseModel):
    """Request a tamper-evident, bounded audit export (admin approval required)."""

    model_config = ConfigDict(extra="forbid")

    requested_from: datetime
    requested_to: datetime
    capability: str | None = Field(default=None, max_length=128)
    ticket_id: str | None = Field(default=None, max_length=128)
    approval_id: str = Field(min_length=1, max_length=128)


class AuditExportResponse(BaseModel):
    """Export receipt (content delivered out-of-band or via status polling)."""

    model_config = ConfigDict(extra="forbid")

    export_id: str = Field(min_length=1, max_length=128)
    state: str = Field(min_length=1, max_length=32)
    status_url: str | None = Field(default=None, max_length=512)
