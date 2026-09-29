"""Group schemas: CRUD, membership add/remove, attribute updates."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.api.schemas.common import ApprovalContext

GroupScope = Literal["GLOBAL", "UNIVERSAL", "DOMAIN_LOCAL"]
GroupCategory = Literal["SECURITY", "DISTRIBUTION"]

GROUP_WRITABLE_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "displayName",
        "description",
        "mail",
        "info",
        "managedBy",
    }
)


class CreateGroupRequest(BaseModel):
    """Create a group inside a managed parent OU."""

    model_config = ConfigDict(extra="forbid")

    parent_ou: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=256)
    scope: GroupScope
    category: GroupCategory = "SECURITY"
    description: str | None = Field(default=None, max_length=1024)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class UpdateGroupAttributesRequest(BaseModel):
    """Update allowlisted group attributes via staged diff."""

    model_config = ConfigDict(extra="forbid")

    attributes: dict[str, Any] = Field(min_length=1, max_length=64)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class RenameGroupRequest(BaseModel):
    """Rename a group (objectGUID invariant, verified read-after-write)."""

    model_config = ConfigDict(extra="forbid")

    new_rdn: str = Field(min_length=1, max_length=256)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class MoveGroupRequest(BaseModel):
    """Move a group between managed OUs."""

    model_config = ConfigDict(extra="forbid")

    destination_ou: str = Field(min_length=1, max_length=1024)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class DeleteGroupRequest(BaseModel):
    """Delete a group (non-privileged, membership policy enforced server-side)."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=512)
    approval: ApprovalContext
    dry_run: bool = False


class MemberAddRequest(BaseModel):
    """Add one member to a group (idempotent: present member is NO_OP)."""

    model_config = ConfigDict(extra="forbid")

    member_guid: str = Field(min_length=1, max_length=64)
    member_type: Literal["USER", "GROUP"] = "USER"
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class MemberRemoveRequest(BaseModel):
    """Remove one member from a group (idempotent: absent member is NO_OP)."""

    model_config = ConfigDict(extra="forbid")

    member_guid: str = Field(min_length=1, max_length=64)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False
