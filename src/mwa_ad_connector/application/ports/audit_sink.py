"""Audit sink port.

Append-only, tamper-evident audit surface. Implementations hash-chain
entries and redact secrets before persistence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID


class AuditEvent(Protocol):
    """Structural audit event (implemented as a pydantic model later)."""

    @property
    def audit_id(self) -> str:
        """Return the audit record identifier."""
        ...


class AuditSink(Protocol):
    """Abstract audit store."""

    async def append(  # noqa: PLR0913 -- port signature mirrors the audit event contract
        self,
        operation_id: str,
        capability: str,
        tenant_id: str,
        connector_id: str,
        caller_subject: str,
        target_guid: UUID | None,
        outcome: str,
        redacted_details: dict[str, str],
        occurred_at: datetime,
    ) -> str:
        """Append a redacted audit event and return its audit id.

        Args:
            operation_id: Linked operation identifier.
            capability: Executed capability.
            tenant_id: Tenant boundary.
            connector_id: Connector boundary.
            caller_subject: Redacted caller label.
            target_guid: Target GUID when known.
            outcome: Outcome label (e.g. AUTHORIZED, AD_VERIFIED).
            redacted_details: Redacted key/value details (no secrets).
            occurred_at: Event timestamp (timezone-aware).

        Returns:
            Audit record identifier / chain reference.
        """
        ...

    async def get(self, audit_id: str) -> dict[str, str] | None:
        """Fetch a redacted audit record by id.

        Args:
            audit_id: Audit identifier.

        Returns:
            Redacted record map or None when absent.
        """
        ...
