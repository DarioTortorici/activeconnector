"""Versioned command envelope (schema 1.0, allowlisted capabilities).

The wire model reuses domain contracts (:class:`ObjectReference`,
domain :class:`ApprovalContext`, capability catalog) and converts to the
domain :class:`CapabilityRequest` consumed by the orchestrator.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mwa_ad_connector.domain.capabilities import is_known_capability, is_mutation_capability
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.domain.operations import ApprovalContext, CapabilityRequest

#: Per-capability parameter allowlist (extra keys are rejected).
PARAMETER_ALLOWLIST: dict[str, frozenset[str]] = {
    "group.member.add": frozenset({"member"}),
    "group.member.remove": frozenset({"member"}),
    "account.password.reset": frozenset({"password"}),
    "account.password.force_change": frozenset({"force"}),
    "user.attributes.update": frozenset({"attributes"}),
    "group.attributes.update": frozenset({"attributes"}),
    "user.rename": frozenset({"new_rdn"}),
    "group.rename": frozenset({"new_rdn"}),
    "ou.rename": frozenset({"new_rdn"}),
    "user.move": frozenset({"destination_ou_dn"}),
    "group.move": frozenset({"destination_ou_dn"}),
    "ou.move": frozenset({"destination_parent_dn"}),
    "user.create": frozenset({"parent_dn", "rdn", "attributes"}),
    "group.create": frozenset({"parent_dn", "name", "attributes"}),
    "ou.create": frozenset({"parent_dn", "name"}),
    "account.enable": frozenset(),
    "account.disable": frozenset({"reason"}),
    "account.unlock": frozenset(),
    "user.delete": frozenset({"reason"}),
    "group.delete": frozenset({"reason"}),
    "ou.delete": frozenset({"require_empty"}),
    "user.search": frozenset({"query", "page_size", "page_token"}),
    "group.search": frozenset({"query", "page_size", "page_token"}),
    "group.members.list": frozenset({"page_size", "page_token"}),
    "user.get": frozenset({"projection"}),
    "group.get": frozenset({"projection"}),
}


class CommandEnvelope(BaseModel):
    """Inbound command envelope, schema version 1.0.

    Attributes:
        schema_version: Always ``1.0`` (maps to ``api_version``).
        capability: Allowlisted capability from the domain catalog.
        customer_id/tenant_id/connector_id/forest_id/domain_id: Scope binding.
        target: Target object reference.
        parameters: Capability-specific parameters (no extras).
        dry_run: Preflight without mutation.
        idempotency_key: Dedup key (required for mutations).
        correlation_id: Correlation identifier for tracing.
        ticket_id: Ticket binding (required for mutations).
        requested_at/expires_at: Validity window.
        nonce: Single-use anti-replay value.
        approval_context: Approval evidence for gated capabilities.
        expected_version: Concurrency token.
        requested_by: Requesting identity label.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    capability: str = Field(min_length=1, max_length=64)
    customer_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    connector_id: str = Field(min_length=1, max_length=128)
    forest_id: str = Field(min_length=1, max_length=128)
    domain_id: str = Field(min_length=1, max_length=128)
    target: ObjectReference
    parameters: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    ticket_id: str | None = Field(default=None, min_length=1, max_length=128)
    requested_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=8, max_length=128)
    approval_context: ApprovalContext | None = None
    expected_version: str | None = Field(default=None, min_length=1, max_length=256)
    requested_by: str = Field(min_length=1, max_length=256)

    @field_validator("capability")
    @classmethod
    def _allowlisted(cls, value: str) -> str:
        if not is_known_capability(value):
            raise ValueError(f"capability not allowlisted: {value}")
        return value

    @model_validator(mode="after")
    def _check_time_scope_params(self) -> CommandEnvelope:
        if self.expires_at <= self.requested_at:
            raise ValueError("expires_at must be after requested_at")
        if self.expires_at < datetime.now(UTC):
            raise ValueError("envelope already expired")
        if self.target.domain_id != self.domain_id or self.target.forest_id != self.forest_id:
            raise ValueError("target scope must match envelope scope")
        if is_mutation_capability(self.capability) and not self.dry_run:
            if self.idempotency_key is None:
                raise ValueError("idempotency_key is required for mutations")
            if self.ticket_id is None:
                raise ValueError("ticket_id is required for mutations")
            if not self.target.has_stable_identity:
                raise ValueError("mutations require target object_guid")
        allowed = PARAMETER_ALLOWLIST.get(self.capability, frozenset())
        extra = set(self.parameters) - set(allowed)
        if extra:
            raise ValueError(f"unknown parameters for {self.capability}: {sorted(extra)}")
        return self

    def to_capability_request(self) -> CapabilityRequest:
        """Convert the wire envelope to the domain capability request.

        Returns:
            Domain ``CapabilityRequest`` for the orchestrator.
        """
        return CapabilityRequest(
            api_version=self.schema_version,
            capability=self.capability,
            customer_id=self.customer_id,
            tenant_id=self.tenant_id,
            connector_id=self.connector_id,
            forest_id=self.forest_id,
            domain_id=self.domain_id,
            target=self.target,
            parameters=self.parameters,
            dry_run=self.dry_run,
            idempotency_key=self.idempotency_key,
            correlation_id=self.correlation_id,
            ticket_id=self.ticket_id,
            requested_at=self.requested_at,
            expires_at=self.expires_at,
            nonce=self.nonce,
            approval_context=self.approval_context,
            expected_version=self.expected_version,
            requested_by=self.requested_by,
        )
