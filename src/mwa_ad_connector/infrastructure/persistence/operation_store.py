"""Operation store: atomic reservations, state transitions, listing (Step 9).

``SqliteOperationStore`` is the production implementation (WAL-capable
file DB or ``:memory:``); ``InMemoryOperationStore`` is its isolated
in-memory alias for unit tests. Both enforce
``UNIQUE(tenant_id, connector_id, idempotency_key)`` and validate every
transition through the lifecycle state machine.

The embedded DDL mirrors ``migrations/0001_init.sql`` (canonical for
deployments). Synchronous SQLite calls run under an ``asyncio.Lock``;
this is deliberate for a low-volume on-prem connector and keeps
transitions atomic without a thread pool.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Collection
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.operations.idempotency import IdempotencyClaim, IdempotencyCollision
from mwa_ad_connector.operations.state_machine import InvalidTransition, can_transition

_DDL = """
CREATE TABLE IF NOT EXISTS operations (
  operation_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  customer_id TEXT NOT NULL DEFAULT '',
  forest_id TEXT NOT NULL DEFAULT '',
  domain_id TEXT NOT NULL DEFAULT '',
  capability TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connector_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS operation_transitions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE CASCADE,
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL,
  changed_at TEXT NOT NULL
);
"""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.isoformat()


class StoredOperation(BaseModel):
    """Persisted operation header (plan section 6.9, minimal subset)."""

    model_config = ConfigDict(extra="forbid")

    operation_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    connector_id: str = Field(min_length=1)
    customer_id: str = ""
    forest_id: str = ""
    domain_id: str = ""
    capability: str = ""
    idempotency_key: str = Field(min_length=1)
    request_hash: str = Field(min_length=1)
    state: str = Field(min_length=1)
    created_at: datetime
    updated_at: datetime


def _row_to_operation(row: dict[str, object]) -> StoredOperation:
    return StoredOperation(
        operation_id=str(row["operation_id"]),
        tenant_id=str(row["tenant_id"]),
        connector_id=str(row["connector_id"]),
        customer_id=str(row.get("customer_id") or ""),
        forest_id=str(row.get("forest_id") or ""),
        domain_id=str(row.get("domain_id") or ""),
        capability=str(row.get("capability") or ""),
        idempotency_key=str(row["idempotency_key"]),
        request_hash=str(row["request_hash"]),
        state=str(row["state"]),
        created_at=datetime.fromisoformat(str(row["created_at"])),
        updated_at=datetime.fromisoformat(str(row["updated_at"])),
    )


class SqliteOperationStore:
    """SQLite-backed operation store with atomic transitions."""

    def __init__(self, db_path: str = ":memory:") -> None:
        """Open the database and ensure the schema exists."""
        self._db_path = db_path
        self._lock = asyncio.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_DDL)
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def _fetch_by_key(self, tenant_id: str, connector_id: str, idempotency_key: str) -> StoredOperation | None:
        row = self._conn.execute(
            "SELECT * FROM operations WHERE tenant_id = ? AND connector_id = ? AND idempotency_key = ?",
            (tenant_id, connector_id, idempotency_key),
        ).fetchone()
        return _row_to_operation(dict(row)) if row is not None else None

    async def reserve(  # noqa: PLR0913 - explicit reservation dimensions
        self,
        *,
        tenant_id: str,
        connector_id: str,
        idempotency_key: str,
        request_hash: str,
        operation_id: str,
        capability: str = "",
        customer_id: str = "",
        forest_id: str = "",
        domain_id: str = "",
        state: str = "RECEIVED",
        now: datetime | None = None,
    ) -> tuple[StoredOperation, bool]:
        """Atomically insert or fetch the reservation; detect hash collisions."""
        async with self._lock:
            current = _iso(now or _utcnow())
            try:
                self._conn.execute(
                    "INSERT INTO operations (operation_id, tenant_id, connector_id, customer_id,"
                    " forest_id, domain_id, capability, idempotency_key, request_hash, state,"
                    " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        operation_id,
                        tenant_id,
                        connector_id,
                        customer_id,
                        forest_id,
                        domain_id,
                        capability,
                        idempotency_key,
                        request_hash,
                        state,
                        current,
                        current,
                    ),
                )
                self._conn.execute(
                    "INSERT INTO operation_transitions (operation_id, from_state, to_state, changed_at)"
                    " VALUES (?, '', ?, ?)",
                    (operation_id, state, current),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                self._conn.rollback()
                existing = self._fetch_by_key(tenant_id, connector_id, idempotency_key)
                if existing is None:  # pragma: no cover - race on operation_id PK
                    raise
                if existing.request_hash != request_hash:
                    raise IdempotencyCollision(
                        existing.operation_id, reason="idempotency key reused with different payload"
                    ) from None
                return existing, False
            record = self._fetch_by_key(tenant_id, connector_id, idempotency_key)
            if record is None:  # pragma: no cover - just inserted
                raise RuntimeError("reservation insert did not persist")
            return record, True

    async def claim_idempotency(
        self,
        *,
        tenant_id: str,
        connector_id: str,
        idempotency_key: str,
        request_hash: str,
        operation_id: str,
    ) -> IdempotencyClaim:
        """Implement the idempotency repository port."""
        record, created = await self.reserve(
            tenant_id=tenant_id,
            connector_id=connector_id,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            operation_id=operation_id,
        )
        return IdempotencyClaim(created=created, operation_id=record.operation_id, stored_hash=record.request_hash)

    async def find_idempotency(
        self,
        *,
        tenant_id: str,
        connector_id: str,
        idempotency_key: str,
    ) -> IdempotencyClaim | None:
        """Return the existing claim for the key, if any."""
        async with self._lock:
            record = self._fetch_by_key(tenant_id, connector_id, idempotency_key)
            if record is None:
                return None
            return IdempotencyClaim(created=False, operation_id=record.operation_id, stored_hash=record.request_hash)

    async def get(self, operation_id: str) -> StoredOperation | None:
        """Return the operation header, if present."""
        async with self._lock:
            row = self._conn.execute("SELECT * FROM operations WHERE operation_id = ?", (operation_id,)).fetchone()
            return _row_to_operation(dict(row)) if row is not None else None

    async def update_state(
        self,
        operation_id: str,
        new_state: str,
        *,
        expected: str | None = None,
        now: datetime | None = None,
    ) -> StoredOperation:
        """Advance state atomically (row update + history) after validation."""
        async with self._lock:
            row = self._conn.execute("SELECT * FROM operations WHERE operation_id = ?", (operation_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown operation: {operation_id!r}")
            record = _row_to_operation(dict(row))
            if expected is not None and record.state != expected:
                raise ValueError(f"expected state {expected!r}, found {record.state!r}")
            if not can_transition(record.state, new_state):
                raise InvalidTransition(record.state, new_state)
            changed = _iso(now or _utcnow())
            self._conn.execute(
                "UPDATE operations SET state = ?, updated_at = ? WHERE operation_id = ?",
                (new_state, changed, operation_id),
            )
            self._conn.execute(
                "INSERT INTO operation_transitions (operation_id, from_state, to_state, changed_at)"
                " VALUES (?, ?, ?, ?)",
                (operation_id, record.state, new_state, changed),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM operations WHERE operation_id = ?", (operation_id,)).fetchone()
            if row is None:  # pragma: no cover - just updated
                raise RuntimeError("operation vanished during state update")
            return _row_to_operation(dict(row))

    async def list(
        self,
        *,
        tenant_id: str | None = None,
        connector_id: str | None = None,
        state: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[StoredOperation]:
        """List headers with allowlisted filters (no free-form search)."""
        query = "SELECT * FROM operations"
        clauses: list[str] = []
        params: list[str] = []
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if connector_id is not None:
            clauses.append("connector_id = ?")
            params.append(connector_id)
        if state is not None:
            clauses.append("state = ?")
            params.append(state)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at ASC LIMIT ? OFFSET ?"
        async with self._lock:
            rows = self._conn.execute(query, (*params, limit, offset)).fetchall()
            return [_row_to_operation(dict(row)) for row in rows]

    async def count_terminal_before(self, cutoff: datetime, *, terminal_states: Collection[str]) -> int:
        """Count terminal records updated before ``cutoff``."""
        states = list(terminal_states)
        if not states:
            return 0
        placeholders = ",".join("?" for _ in states)
        async with self._lock:
            # Placeholders below are generated "?" tokens; values stay bound parameters.
            row = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM operations WHERE state IN ({placeholders})"  # noqa: S608
                " AND updated_at < ?",
                (*states, _iso(cutoff)),
            ).fetchone()
            return int(row["n"])

    async def purge_terminal_before(self, cutoff: datetime, *, terminal_states: Collection[str]) -> int:
        """Delete terminal records updated before ``cutoff``; return the count."""
        states = list(terminal_states)
        if not states:
            return 0
        placeholders = ",".join("?" for _ in states)
        async with self._lock:
            # Placeholders below are generated "?" tokens; values stay bound parameters.
            cursor = self._conn.execute(
                f"DELETE FROM operations WHERE state IN ({placeholders}) AND updated_at < ?",  # noqa: S608
                (*states, _iso(cutoff)),
            )
            self._conn.commit()
            return cursor.rowcount if cursor.rowcount is not None else 0


class InMemoryOperationStore(SqliteOperationStore):
    """In-memory operation store for unit tests (isolated SQLite ``:memory:``)."""

    def __init__(self) -> None:
        """Create an isolated in-memory database."""
        super().__init__(db_path=":memory:")
