# Persistence migrations

Canonical SQL schema for the connector's local stores (Steps 8-9):

- `0001_init.sql` creates `operations` (+ `UNIQUE(tenant_id, connector_id,
  idempotency_key)`), `operation_transitions`, `audit_entries`
  (hash-chained, tamper-evident) and `nonces` (anti-replay with TTL).

Conventions:

- New changes add a sequentially numbered file (`0002_*.sql`); never edit
  an applied migration.
- Store modules (`operation_store.py`, `audit_store.py`, `nonce_store.py`)
  embed an equivalent DDL for zero-config startup; this directory is the
  canonical reference for managed deployments.
- Timestamps are UTC ISO-8601 strings; nonce expiries are epoch seconds.
- No secrets are ever persisted: passwords, tokens and private key
  material must not appear in any table.
