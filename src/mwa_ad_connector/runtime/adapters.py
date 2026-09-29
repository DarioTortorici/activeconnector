"""Runtime adapters: caller mapping, operation repository and audit sink bridges."""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.domain.capabilities import get_metadata, is_known_capability
from mwa_ad_connector.domain.enums import OperationState
from mwa_ad_connector.domain.errors import ConcurrentModificationError, IdempotencyCollisionError
from mwa_ad_connector.domain.operations import CallerContext, OperationRecord, StateTransition
from mwa_ad_connector.security.redaction import redact_dict


class Clock(Protocol):
    """Minimal clock surface used by the composition root."""

    def now(self) -> datetime:
        """Return the current timezone-aware timestamp."""
        ...  # pragma: no cover

    def monotonic(self) -> float:
        """Return a monotonic timestamp for timeouts."""
        ...  # pragma: no cover


class SystemClock:
    """Default clock backed by the system time."""

    def now(self) -> datetime:
        """Return the current UTC timestamp."""
        return datetime.now(UTC)

    def monotonic(self) -> float:
        """Return the monotonic clock reading."""
        return time.monotonic()


def _field(source: Any, name: str, default: Any = None) -> Any:  # noqa: ANN401 - duck-typed caller input.
    """Read a field from a mapping or object caller context."""
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _as_aware(value: Any) -> datetime | None:  # noqa: ANN401 - duck-typed timestamp input.
    """Coerce a datetime-like value to an aware datetime, else None."""
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return None


def caller_to_domain(caller: Any, settings: ConnectorSettings, *, now: datetime | None = None) -> CallerContext:  # noqa: ANN401
    """Map an API caller (model or mapping) to the canonical domain CallerContext.

    Missing boundary fields fall back to the local connector settings so
    worker-originated calls stay bound to this instance.

    Args:
        caller: API caller context, mapping, or arbitrary object.
        settings: Local connector settings providing fallback boundaries.
        now: Authentication timestamp fallback.

    Returns:
        Canonical domain caller context.
    """
    scopes = [str(scope) for scope in (_field(caller, "scopes", []) or [])]
    roles = [str(role) for role in (_field(caller, "roles", []) or [])]
    thumbprint = _field(caller, "certificate_thumbprint")
    return CallerContext(
        subject=str(_field(caller, "subject", "unknown") or "unknown"),
        issuer=str(_field(caller, "issuer", "local") or "local"),
        audience=str(_field(caller, "audience", settings.connector_id) or settings.connector_id),
        tenant_id=str(_field(caller, "tenant_id", settings.tenant_id) or settings.tenant_id),
        customer_id=str(_field(caller, "customer_id", settings.customer_id) or settings.customer_id),
        connector_id=str(_field(caller, "connector_id", settings.connector_id) or settings.connector_id),
        scopes=scopes,
        roles=roles,
        certificate_thumbprint=str(thumbprint) if thumbprint else None,
        auth_method=str(_field(caller, "auth_method", "jwt-bearer") or "jwt-bearer"),
        token_id=str(_field(caller, "token_id") or "untracked"),
        authenticated_at=_as_aware(_field(caller, "authenticated_at")) or now or datetime.now(UTC),
    )


def _record_from_stored(stored: Any) -> OperationRecord | None:  # noqa: ANN401 - duck-typed store row.
    """Rebuild a best-effort OperationRecord from a persisted store row."""
    capability = str(getattr(stored, "capability", "") or "")
    if not is_known_capability(capability):
        return None
    try:
        state = OperationState(str(stored.state))
    except ValueError:
        return None
    created = _as_aware(getattr(stored, "created_at", None)) or datetime.now(UTC)
    updated = _as_aware(getattr(stored, "updated_at", None)) or created
    try:
        return OperationRecord(
            operation_id=str(stored.operation_id),
            customer_id=str(stored.customer_id or "unknown"),
            tenant_id=str(stored.tenant_id),
            connector_id=str(stored.connector_id),
            forest_id=str(stored.forest_id or "unknown"),
            domain_id=str(stored.domain_id or "unknown"),
            capability=capability,
            risk=get_metadata(capability).risk,
            request_hash=str(stored.request_hash),
            idempotency_key=str(stored.idempotency_key),
            correlation_id="unknown",
            ticket_id=None,
            caller_subject="unknown",
            target_guid=None,
            state=state,
            history=[],
            selected_dc=None,
            created_at=created,
            updated_at=updated,
            deadline=created,
        )
    except ValueError:
        return None


class OperationRepositoryAdapter:
    """Bridge the SQLite operation store to the canonical repository port.

    Full ``OperationRecord`` values are cached in memory so the orchestrator
    can replay idempotent requests with their evidence; persisted rows remain
    the durable source of truth for state and listing.

    Args:
        store: Raw operation store (e.g. ``SqliteOperationStore``).
    """

    def __init__(self, store: Any) -> None:  # noqa: ANN401 - store shape is duck-typed.
        self._store = store
        self._records: dict[str, OperationRecord] = {}

    @property
    def store(self) -> Any:  # noqa: ANN401 - raw store access for health/list paths.
        """Return the wrapped raw store."""
        return self._store

    def cached(self, operation_id: str) -> OperationRecord | None:
        """Return the in-memory record when this process created it."""
        return self._records.get(operation_id)

    async def save(self, record: OperationRecord) -> None:
        """Persist a new operation record (fails on key reuse)."""
        stored, created = await self._store.reserve(
            tenant_id=record.tenant_id,
            connector_id=record.connector_id,
            idempotency_key=record.idempotency_key,
            request_hash=record.request_hash,
            operation_id=record.operation_id,
            capability=record.capability,
            customer_id=record.customer_id,
            forest_id=record.forest_id,
            domain_id=record.domain_id,
            state=record.state.value,
            now=record.created_at,
        )
        if not created:
            if stored.request_hash != record.request_hash:
                raise IdempotencyCollisionError("idempotency key reused with a different payload")
            raise ConcurrentModificationError("operation with this key is already in progress")
        self._records[record.operation_id] = record

    async def get(self, operation_id: str) -> OperationRecord | None:
        """Fetch a record by operation id (cache first, persisted fallback)."""
        stored = await self._store.get(operation_id)
        if stored is None:
            return None
        cached = self._records.get(operation_id)
        if cached is None:
            return _record_from_stored(stored)
        try:
            state = OperationState(str(stored.state))
        except ValueError:
            state = cached.state
        updated = _as_aware(getattr(stored, "updated_at", None)) or cached.updated_at
        return cached.model_copy(update={"state": state, "updated_at": updated})

    async def get_by_idempotency_key(
        self, tenant_id: str, connector_id: str, idempotency_key: str
    ) -> OperationRecord | None:
        """Fetch a record by its idempotency triple."""
        finder = getattr(self._store, "find_idempotency", None)
        if finder is None:
            return None
        claim = await finder(tenant_id=tenant_id, connector_id=connector_id, idempotency_key=idempotency_key)
        if claim is None:
            return None
        return await self.get(str(claim.operation_id))

    async def transition(self, operation_id: str, to_state: OperationState, reason: str = "") -> OperationRecord:
        """Advance the persisted state and mirror it into the cached record."""
        updated = await self._store.update_state(operation_id, to_state.value)
        cached = self._records.get(operation_id)
        if cached is None:
            rebuilt = _record_from_stored(updated)
            if rebuilt is None:
                raise KeyError(operation_id)
            return rebuilt
        moment = _as_aware(getattr(updated, "updated_at", None)) or datetime.now(UTC)
        moved = cached.model_copy(
            update={
                "state": to_state,
                "updated_at": moment,
                "history": [
                    *cached.history,
                    StateTransition(from_state=cached.state, to_state=to_state, at=moment, reason=reason),
                ],
            }
        )
        self._records[operation_id] = moved
        return moved

    async def list_by_state(self, state: OperationState | None = None, limit: int = 50) -> list[OperationRecord]:
        """List records optionally filtered by state."""
        rows = await self._store.list(state=state.value if state is not None else None, limit=limit)
        records: list[OperationRecord] = []
        for row in rows:
            record = await self.get(str(row.operation_id))
            if record is not None:
                records.append(record)
        return records

    async def list_stored(self, **filters: Any) -> list[Any]:  # noqa: ANN401 - pass-through filters.
        """List raw persisted rows with allowlisted filters."""
        return list(await self._store.list(**filters))


class AuditSinkAdapter:
    """Bridge the hash-chained audit store to the canonical audit sink port.

    Args:
        store: Raw audit store (e.g. ``HashChainedAuditStore``).
    """

    def __init__(self, store: Any) -> None:  # noqa: ANN401 - store shape is duck-typed.
        self._store = store

    @property
    def store(self) -> Any:  # noqa: ANN401 - raw store access for export/verify paths.
        """Return the wrapped raw store."""
        return self._store

    async def append(  # noqa: PLR0913 - port signature mirrors the audit event contract.
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
        """Append a redacted audit event and return its entry key."""
        payload: dict[str, Any] = {
            "operation_id": operation_id,
            "stage": outcome,
            "capability": capability,
            "tenant_id": tenant_id,
            "connector_id": connector_id,
            "caller_subject": caller_subject,
            "target_guid": str(target_guid) if target_guid is not None else None,
            "details": redact_dict(redacted_details),
            "recorded_at": occurred_at.isoformat(),
        }
        return str(await self._store.append(payload))

    async def get(self, audit_id: str) -> dict[str, str] | None:
        """Fetch a redacted audit record by entry key."""
        record = await self._store.get(audit_id)
        if record is None:
            return None
        return {str(key): str(value) for key, value in record.items()}
