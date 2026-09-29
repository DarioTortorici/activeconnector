"""Nonce stores with TTL: in-memory and SQLite (Steps 8-9).

Both implement the :class:`NonceStore` port consumed by
:class:`AntiReplayService`: ``claim`` is single-use (second claim inside
the TTL returns False) and ``purge_expired`` reaps dead entries.
Synchronous by design: nonce checks run inside request validation where
an event loop may not be available.
"""

from __future__ import annotations

import sqlite3
import threading
import time

_NONCE_DDL = """
CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  expires_at REAL NOT NULL
);
"""


class InMemoryNonceStore:
    """Thread-safe in-memory nonce store for tests and single-process use."""

    def __init__(self) -> None:
        """Create an empty nonce index."""
        self._lock = threading.Lock()
        self._entries: dict[str, float] = {}

    def claim(self, nonce: str, expires_at: float) -> bool:
        """Claim ``nonce`` once; False when already claimed and unexpired."""
        with self._lock:
            existing = self._entries.get(nonce)
            if existing is not None and existing > time.time():
                return False
            self._entries[nonce] = expires_at
            return True

    def purge_expired(self, now: float) -> int:
        """Delete entries at or before ``now``; return the removed count."""
        with self._lock:
            expired = [nonce for nonce, expiry in self._entries.items() if expiry <= now]
            for nonce in expired:
                del self._entries[nonce]
            return len(expired)


class SqliteNonceStore:
    """SQLite-backed nonce store for multi-process durability."""

    def __init__(self, db_path: str = ":memory:") -> None:
        """Open the database and ensure the schema exists."""
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_NONCE_DDL)
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def claim(self, nonce: str, expires_at: float) -> bool:
        """Claim ``nonce`` once; False when already claimed and unexpired."""
        with self._lock:
            try:
                self._conn.execute("INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)", (nonce, expires_at))
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                row = self._conn.execute("SELECT expires_at FROM nonces WHERE nonce = ?", (nonce,)).fetchone()
                if row is None:  # pragma: no cover - deleted between statements
                    return False
                if float(row[0]) <= time.time():
                    self._conn.execute("UPDATE nonces SET expires_at = ? WHERE nonce = ?", (expires_at, nonce))
                    self._conn.commit()
                    return True
                return False

    def purge_expired(self, now: float) -> int:
        """Delete entries at or before ``now``; return the removed count."""
        with self._lock:
            cursor = self._conn.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
            self._conn.commit()
            return cursor.rowcount if cursor.rowcount is not None else 0
