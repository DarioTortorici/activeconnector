"""Organizational unit schemas: create, rename, move, delete (empty-only)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.api.schemas.common import ApprovalContext


class CreateOuRequest(BaseModel):
    """Create a child OU under a managed parent scope."""

    model_config = ConfigDict(extra="forbid")

    parent: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=1024)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class RenameOuRequest(BaseModel):
    """Rename an OU (objectGUID invariant, verified read-after-write)."""

    model_config = ConfigDict(extra="forbid")

    new_rdn: str = Field(min_length=1, max_length=256)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class MoveOuRequest(BaseModel):
    """Move an OU subtree within managed scope (preflight enforced server-side)."""

    model_config = ConfigDict(extra="forbid")

    destination_parent: str = Field(min_length=1, max_length=1024)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext
    dry_run: bool = False


class DeleteOuRequest(BaseModel):
    """Delete an OU (empty and unprotected only; require_empty defaults True)."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=512)
    approval: ApprovalContext
    require_empty: bool = True
    dry_run: bool = False
