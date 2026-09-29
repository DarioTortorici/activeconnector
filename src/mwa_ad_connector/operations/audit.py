"""Audit service: requested/before/after/commit/verify events via AuditSink (Step 9).

Every event is redacted before reaching the sink: DNs are masked for
logs and secret-bearing detail values are replaced. The sink (hash-chained
store) assigns entry ids and chaining hashes.

The :class:`AuditSink` protocol mirrors ``application.ports.audit_sink``
(owned by another agent); unify on it when available.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.security.redaction import redact_dict, redact_dn_for_logs


class AuditStage(StrEnum):
    """Lifecycle moment an audit event records (plan section 6.9)."""

    REQUESTED = "REQUESTED"
    BEFORE = "BEFORE"
    AFTER = "AFTER"
    COMMIT = "COMMIT"
    VERIFY = "VERIFY"


class AuditEntry(BaseModel):
    """Single redacted audit event (entry id assigned by the sink)."""

    model_config = ConfigDict(extra="forbid")

    operation_id: str = Field(min_length=1)
    stage: AuditStage
    capability: str = ""
    tenant_id: str = ""
    connector_id: str = ""
    caller_subject: str | None = None
    target_dn: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditSink(Protocol):
    """Persistence port for audit events."""

    async def append(self, entry: AuditEntry) -> str:
        """Persist ``entry`` and return its tamper-evident entry id."""
        ...  # pragma: no cover


class AuditService:
    """Record redacted audit events through an :class:`AuditSink`."""

    def __init__(self, sink: AuditSink) -> None:
        """Bind the service to its sink."""
        self._sink = sink

    async def record(  # noqa: PLR0913 - explicit audit dimensions beat **kwargs opacity
        self,
        stage: AuditStage,
        *,
        operation_id: str,
        capability: str = "",
        tenant_id: str = "",
        connector_id: str = "",
        caller_subject: str | None = None,
        target_dn: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> str:
        """Build a redacted entry for ``stage`` and append it to the sink."""
        entry = AuditEntry(
            operation_id=operation_id,
            stage=stage,
            capability=capability,
            tenant_id=tenant_id,
            connector_id=connector_id,
            caller_subject=caller_subject,
            target_dn=redact_dn_for_logs(target_dn) if target_dn is not None else None,
            details=redact_dict(dict(details) if details is not None else {}),
        )
        return await self._sink.append(entry)

    async def log_requested(self, **kwargs: Any) -> str:
        """Record envelope acceptance (before policy evaluation)."""
        return await self.record(AuditStage.REQUESTED, **kwargs)

    async def log_before(self, **kwargs: Any) -> str:
        """Record the pre-mutation snapshot (state before the LDAP write)."""
        return await self.record(AuditStage.BEFORE, **kwargs)

    async def log_after(self, **kwargs: Any) -> str:
        """Record the post-commit observation (after the LDAP write)."""
        return await self.record(AuditStage.AFTER, **kwargs)

    async def log_commit(self, **kwargs: Any) -> str:
        """Record DC acceptance of the mutation (AD_COMMITTED)."""
        return await self.record(AuditStage.COMMIT, **kwargs)

    async def log_verify(self, **kwargs: Any) -> str:
        """Record the read-after-write outcome (AD_VERIFIED / failed)."""
        return await self.record(AuditStage.VERIFY, **kwargs)
