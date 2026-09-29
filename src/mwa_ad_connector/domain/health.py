"""Health contracts (Section 6.11).

The public health surface stays redacted: no DNs, internal hostnames,
full thumbprints or other sensitive details.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.domain.enums import HealthState


class ComponentHealth(BaseModel):
    """Health of a single dependency or subsystem.

    Attributes:
        state: Component state.
        detail: Redacted human-readable detail (no secrets/hostnames).
        checked_at: Check timestamp (timezone-aware).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: HealthState
    detail: str = Field(default="", max_length=512)
    checked_at: datetime


class HealthStatus(BaseModel):
    """Aggregate connector health snapshot.

    Attributes:
        status: Aggregate state.
        version: Connector build version.
        connector_id: Local connector identity.
        configuration_valid: Whether startup validation passed.
        operation_store: Operation store health.
        audit_store: Audit store health.
        transport: Command transport health.
        ldap_connectivity: LDAP bind/reachability health.
        ldaps_certificate: Certificate validation health.
        dc_selection: DC selection/pinning health.
        clock_skew: Clock skew check health.
        last_successful_bind: Last bind timestamp when known.
        last_successful_operation: Last verified operation timestamp.
        degraded_reasons: Redacted reasons when not healthy.
        checked_at: Snapshot timestamp (timezone-aware).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: HealthState
    version: str = Field(min_length=1, max_length=64)
    connector_id: str = Field(min_length=1, max_length=128)
    configuration_valid: bool
    operation_store: ComponentHealth
    audit_store: ComponentHealth
    transport: ComponentHealth
    ldap_connectivity: ComponentHealth
    ldaps_certificate: ComponentHealth
    dc_selection: ComponentHealth
    clock_skew: ComponentHealth
    last_successful_bind: datetime | None = None
    last_successful_operation: datetime | None = None
    degraded_reasons: list[str] = Field(default_factory=list)
    checked_at: datetime
