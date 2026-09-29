"""Discovery/read schemas: RootDSE, capabilities, resolve, get, search, members."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.api.schemas.common import PageTokenRequest

ObjectTypeName = Literal["USER", "GROUP", "OU"]


class RootDseResponse(BaseModel):
    """Redacted RootDSE view for one configured domain."""

    model_config = ConfigDict(extra="forbid")

    domain_id: str = Field(min_length=1, max_length=128)
    forest_id: str = Field(min_length=1, max_length=128)
    naming_contexts: list[str] = Field(default_factory=list)
    functional_level: str | None = Field(default=None, max_length=64)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CapabilitiesResponse(BaseModel):
    """Allowlisted capability ids supported for one domain."""

    model_config = ConfigDict(extra="forbid")

    domain_id: str = Field(min_length=1, max_length=128)
    capabilities: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ResolveRequest(BaseModel):
    """Resolve an object by GUID (preferred) or allowlisted identifier."""

    model_config = ConfigDict(extra="forbid")

    object_type: ObjectTypeName
    domain_id: str = Field(min_length=1, max_length=128)
    object_guid: str | None = Field(default=None, max_length=64)
    identifier_type: str | None = Field(default=None, max_length=32)
    identifier_value: str | None = Field(default=None, max_length=512)


class ResolveResponse(BaseModel):
    """Exactly-one resolution outcome (ambiguity is a 409, never a guess)."""

    model_config = ConfigDict(extra="forbid")

    object_type: ObjectTypeName
    object_guid: str = Field(min_length=1, max_length=64)
    distinguished_name: str = Field(min_length=1, max_length=1024)
    domain_id: str = Field(min_length=1, max_length=128)


class GetObjectRequest(BaseModel):
    """Typed read with allowlisted projection."""

    model_config = ConfigDict(extra="forbid")

    projection: list[str] = Field(default_factory=list, max_length=64)


class DirectoryObjectResponse(BaseModel):
    """Redacted directory object view (never contains secrets)."""

    model_config = ConfigDict(extra="forbid")

    object_type: ObjectTypeName
    object_guid: str = Field(min_length=1, max_length=64)
    distinguished_name: str = Field(min_length=1, max_length=1024)
    domain_id: str = Field(min_length=1, max_length=128)
    display_name: str | None = Field(default=None, max_length=512)
    attributes: dict[str, Any] = Field(default_factory=dict)
    version_token: str | None = Field(default=None, max_length=256)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SearchRequest(PageTokenRequest):
    """Predefined query-profile search (raw LDAP filters are forbidden)."""

    model_config = ConfigDict(extra="forbid")

    domain_id: str = Field(min_length=1, max_length=128)
    object_type: ObjectTypeName
    query_profile: str = Field(min_length=1, max_length=128)
    parameters: dict[str, str] = Field(default_factory=dict)


class SearchResponse(BaseModel):
    """Paged search outcome with signed continuation token."""

    model_config = ConfigDict(extra="forbid")

    items: list[DirectoryObjectResponse] = Field(default_factory=list)
    next_page_token: str | None = Field(default=None, max_length=4096)


class MembersResponse(BaseModel):
    """Paged group membership (unresolved references are flagged, not hidden)."""

    model_config = ConfigDict(extra="forbid")

    group_guid: str = Field(min_length=1, max_length=64)
    members: list[ResolveResponse] = Field(default_factory=list)
    unresolved_count: int = Field(default=0, ge=0)
    next_page_token: str | None = Field(default=None, max_length=4096)
