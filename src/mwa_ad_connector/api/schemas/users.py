"""User lifecycle schemas: create, update (allowlisted), rename, move, delete."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.api.schemas.common import ApprovalContext

# Attributes writable through user.attributes.update (schema-level guard; policy enforces per-profile).
USER_WRITABLE_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "displayName",
        "givenName",
        "sn",
        "description",
        "title",
        "department",
        "company",
        "telephoneNumber",
        "mobile",
        "mail",
        "streetAddress",
        "l",
        "st",
        "postalCode",
        "c",
        "co",
        "countryCode",
        "employeeID",
        "employeeType",
        "manager",
        "info",
    }
)


class CreateUserRequest(BaseModel):
    """Create a user inside a managed parent OU."""

    model_config = ConfigDict(extra="forbid")

    parent_ou: str = Field(min_length=1, max_length=1024)
    sam_account_name: str = Field(min_length=1, max_length=64)
    user_principal_name: str | None = Field(default=None, max_length=512)
    display_name: str | None = Field(default=None, max_length=512)
    attributes: dict[str, Any] = Field(default_factory=dict, max_length=64)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class UpdateUserAttributesRequest(BaseModel):
    """Staged-diff update restricted to the allowlisted attribute set."""

    model_config = ConfigDict(extra="forbid")

    attributes: dict[str, Any] = Field(min_length=1, max_length=64)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class RenameUserRequest(BaseModel):
    """Rename (change RDN) of a user; objectGUID must stay invariant."""

    model_config = ConfigDict(extra="forbid")

    new_rdn: str = Field(min_length=1, max_length=256)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class MoveUserRequest(BaseModel):
    """Move a user between two managed OUs."""

    model_config = ConfigDict(extra="forbid")

    destination_ou: str = Field(min_length=1, max_length=1024)
    expected_version: str | None = Field(default=None, max_length=256)
    approval: ApprovalContext | None = None
    dry_run: bool = False


class DeleteUserRequest(BaseModel):
    """Delete a user (approval-gated; disable/stage preferred by policy)."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=512)
    approval: ApprovalContext
    dry_run: bool = False
