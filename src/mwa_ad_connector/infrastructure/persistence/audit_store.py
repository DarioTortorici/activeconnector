"""Hash-chained audit store: tamper-evident append, verify, redacted export (Step 9).

Each entry stores ``entry_hash = sha256(prev_hash + canonical_json)`` so
any alteration breaks :meth:`HashChainedAuditStore.verify_chain`. The
store implements the :class:`AuditSink` port, so
:class:`AuditService` writes here directly. Payloads are expected
pre-redacted; the store never persists raw secrets.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import uuid
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from mwa_ad_connector.operations.audit import AuditEntry, AuditStage

_GENESIS_HASH = "GENESIS"

_DDL = """
CREATE TABLE IF NOT EXISTS audit_entries (
  entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_key TEXT NOT NULL UNIQUE,
  operation_id TEXT NOT NULL DEFAULT '',
  stage TEXT NOT NULL,
  capability TEXT NOT NULL DEFAULT '',
  tenant_id TEXT NOT NULL DEFAULT '',
  connector_id TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL DEFAULT '',
  entry_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


class ChainReport(BaseModel):
    """Outcome of a hash-chain verification pass."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    checked: int
    broken_at: str | None = None


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), default=str)


def _entry_payload(entry: AuditEntry | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(entry, AuditEntry):
        return entry.model_dump(mode="json")
    return dict(entry)


class HashChainedAuditStore:
    """SQLite-backed tamper-evident audit store (``:memory:`` by default)."""

    def __init__(self, db_path: str = ":memory:") -> None:
        """Open the database and ensure the schema exists."""
        self._lock = asyncio.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def _last_hash(self) -> str:
        row = self._conn.execute("SELECT entry_hash FROM audit_entries ORDER BY entry_id DESC LIMIT 1").fetchone()
        return str(row["entry_hash"]) if row is not None else _GENESIS_HASH

    async def append(self, entry: AuditEntry | Mapping[str, Any]) -> str:
        """Append ``entry`` with chaining hash; return the entry key."""
        payload = _entry_payload(entry)
        if "operation_id" not in payload or "stage" not in payload:
            raise ValueError("audit entry requires operation_id and stage")
        stage = payload["stage"]
        stage_name = stage.value if isinstance(stage, AuditStage) else str(stage)
        canonical = _canonical(payload)
        async with self._lock:
            prev = self._last_hash()
            digest = hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()
            key = uuid.uuid4().hex
            created = str(payload.get("recorded_at") or "")
            self._conn.execute(
                "INSERT INTO audit_entries (entry_key, operation_id, stage, capability, tenant_id,"
                " connector_id, payload_json, prev_hash, entry_hash, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    key,
                    str(payload.get("operation_id") or ""),
                    stage_name,
                    str(payload.get("capability") or ""),
                    str(payload.get("tenant_id") or ""),
                    str(payload.get("connector_id") or ""),
                    canonical,
                    prev,
                    digest,
                    created,
                ),
            )
            self._conn.commit()
            return key

    async def get(self, entry_key: str) -> dict[str, Any] | None:
        """Return the stored (redacted) entry, if present."""
        async with self._lock:
            row = self._conn.execute("SELECT * FROM audit_entries WHERE entry_key = ?", (entry_key,)).fetchone()
            if row is None:
                return None
            record = dict(row)
            payload: dict[str, Any] = json.loads(str(record["payload_json"]))
            payload["_entry_key"] = record["entry_key"]
            payload["_entry_hash"] = record["entry_hash"]
            return payload

    async def verify_chain(self) -> ChainReport:
        """Recompute every link; report the first break, if any."""
        async with self._lock:
            rows = self._conn.execute(
                "SELECT entry_key, payload_json, prev_hash, entry_hash FROM audit_entries ORDER BY entry_id ASC"
            ).fetchall()
        prev = _GENESIS_HASH
        checked = 0
        for row in rows:
            canonical = str(row["payload_json"])
            expected = hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()
            if row["prev_hash"] != prev or row["entry_hash"] != expected:
                return ChainReport(valid=False, checked=checked, broken_at=str(row["entry_key"]))
            prev = str(row["entry_hash"])
            checked += 1
        return ChainReport(valid=True, checked=checked)

    async def export(  # noqa: PLR0913 - allowlisted filter dimensions
        self,
        *,
        operation_id: str | None = None,
        tenant_id: str | None = None,
        connector_id: str | None = None,
        stage: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Export stored (redacted) entries with allowlisted filters."""
        query = "SELECT * FROM audit_entries"
        clauses: list[str] = []
        params: list[str] = []
        for column, value in (
            ("operation_id", operation_id),
            ("tenant_id", tenant_id),
            ("connector_id", connector_id),
            ("stage", stage),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY entry_id ASC LIMIT ? OFFSET ?"
        async with self._lock:
            rows = self._conn.execute(query, (*params, limit, offset)).fetchall()
            results: list[dict[str, Any]] = []
            for row in rows:
                record = dict(row)
                payload: dict[str, Any] = json.loads(str(record["payload_json"]))
                payload["_entry_key"] = record["entry_key"]
                payload["_entry_hash"] = record["entry_hash"]
                results.append(payload)
            return results
