-- 0001_init: operations, transitions, audit chain, nonces (Steps 8-9).
-- Canonical schema for deployments; store modules embed an identical DDL
-- for zero-config startup (sqlite file or :memory:).

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

CREATE INDEX IF NOT EXISTS idx_operations_state_updated
  ON operations (state, updated_at);

CREATE TABLE IF NOT EXISTS operation_transitions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE CASCADE,
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL,
  changed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_transitions_operation
  ON operation_transitions (operation_id);

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

CREATE INDEX IF NOT EXISTS idx_audit_operation
  ON audit_entries (operation_id);

CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  expires_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nonces_expiry
  ON nonces (expires_at);
