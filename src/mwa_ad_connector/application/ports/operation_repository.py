"""Operation repository port.

Durable store for OperationRecord lifecycle: idempotent registration,
state transitions and filtered listing with retention applied by the
implementation.
"""

from __future__ import annotations

from typing import Protocol

from mwa_ad_connector.domain.enums import OperationState
from mwa_ad_connector.domain.operations import OperationRecord


class OperationRepository(Protocol):
    """Abstract durable operation store."""

    async def save(self, record: OperationRecord) -> None:
        """Persist a new operation record.

        Args:
            record: Record to persist.

        Raises:
            IdempotencyCollisionError: When the key exists with another hash.
        """
        ...

    async def get(self, operation_id: str) -> OperationRecord | None:
        """Fetch a record by operation id.

        Args:
            operation_id: Operation identifier.

        Returns:
            Record or None when absent.
        """
        ...

    async def get_by_idempotency_key(
        self, tenant_id: str, connector_id: str, idempotency_key: str
    ) -> OperationRecord | None:
        """Fetch a record by its idempotency triple.

        Args:
            tenant_id: Tenant boundary.
            connector_id: Connector boundary.
            idempotency_key: Deduplication key.

        Returns:
            Record or None when absent.
        """
        ...

    async def transition(self, operation_id: str, to_state: OperationState, reason: str = "") -> OperationRecord:
        """Atomically transition an operation to a new state.

        Args:
            operation_id: Operation identifier.
            to_state: Desired next state.
            reason: Redacted reason label.

        Returns:
            Updated record.

        Raises:
            TargetNotFoundError: When the operation is unknown.
            ValueError: On illegal transitions.
        """
        ...

    async def list_by_state(self, state: OperationState | None = None, limit: int = 50) -> list[OperationRecord]:
        """List records optionally filtered by state.

        Args:
            state: Optional state filter.
            limit: Maximum records to return.

        Returns:
            Matching records newest-first (implementation defined).
        """
        ...
