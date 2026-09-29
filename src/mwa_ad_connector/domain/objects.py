"""Typed directory object views (Sections 6.3/6.4).

Views are redacted by construction: they never carry passwords,
unicodePwd, Kerberos tickets or other secrets.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class DirectoryUser(BaseModel):
    """Redacted view of an AD user object.

    Attributes:
        object_guid: Stable AD identity.
        distinguished_name: Current DN observed on the source DC.
        domain_id: Owning domain boundary.
        sam_account_name: sAMAccountName value.
        user_principal_name: UPN value when present.
        display_name: Display name when present.
        enabled: Derived from userAccountControl.
        locked: Derived from lockout state.
        pwd_last_set: Password last-set timestamp when known.
        member_of_guids: Direct parent group GUIDs.
        attributes: Redacted allowlisted attribute view.
        version_token: Opaque concurrency token for expected_version checks.
        source_dc: DC that served the read (for pinning evidence).
        observed_at: Observation timestamp (timezone-aware).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    object_guid: UUID
    distinguished_name: str = Field(min_length=1, max_length=512)
    domain_id: str = Field(min_length=1, max_length=128)
    sam_account_name: str = Field(min_length=1, max_length=256)
    user_principal_name: str | None = Field(default=None, max_length=256)
    display_name: str | None = Field(default=None, max_length=256)
    enabled: bool
    locked: bool
    pwd_last_set: datetime | None = None
    member_of_guids: list[UUID] = Field(default_factory=list)
    attributes: dict[str, str | list[str]] = Field(default_factory=dict)
    version_token: str = Field(min_length=1, max_length=256)
    source_dc: str = Field(min_length=1, max_length=256)
    observed_at: datetime


class DirectoryGroup(BaseModel):
    """Redacted view of an AD group object.

    Attributes:
        object_guid: Stable AD identity.
        distinguished_name: Current DN observed on the source DC.
        domain_id: Owning domain boundary.
        sam_account_name: sAMAccountName value.
        name: Group name (CN).
        group_scope: AD group scope label (e.g. Global, Universal).
        group_category: AD group category label (Security/Distribution).
        member_guids: Direct member object GUIDs.
        is_privileged: Whether the group is classified as privileged.
        protection_reasons: Human-readable reasons for protection flags.
        version_token: Opaque concurrency token.
        source_dc: DC that served the read.
        observed_at: Observation timestamp (timezone-aware).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    object_guid: UUID
    distinguished_name: str = Field(min_length=1, max_length=512)
    domain_id: str = Field(min_length=1, max_length=128)
    sam_account_name: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    group_scope: str = Field(min_length=1, max_length=64)
    group_category: str = Field(min_length=1, max_length=64)
    member_guids: list[UUID] = Field(default_factory=list)
    is_privileged: bool = False
    protection_reasons: list[str] = Field(default_factory=list)
    version_token: str = Field(min_length=1, max_length=256)
    source_dc: str = Field(min_length=1, max_length=256)
    observed_at: datetime


class OrganizationalUnit(BaseModel):
    """Redacted view of an AD organizational unit.

    Attributes:
        object_guid: Stable AD identity.
        distinguished_name: Current DN observed on the source DC.
        domain_id: Owning domain boundary.
        name: OU name (CN component).
        parent_dn: Parent DN for scope checks.
        child_count: Hint for require_empty guards (best effort).
        version_token: Opaque concurrency token.
        source_dc: DC that served the read.
        observed_at: Observation timestamp (timezone-aware).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    object_guid: UUID
    distinguished_name: str = Field(min_length=1, max_length=512)
    domain_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    parent_dn: str = Field(min_length=1, max_length=512)
    child_count: int = Field(default=0, ge=0)
    version_token: str = Field(min_length=1, max_length=256)
    source_dc: str = Field(min_length=1, max_length=256)
    observed_at: datetime
