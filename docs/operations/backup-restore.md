# Backup & restore (Step 21)

## What to back up

- **Operation store**: idempotency keys, state history (exactly-once safety).
- **Audit store**: tamper-evident chain (compliance; append-only, never edited).
- **Config**: connector JSON + trust store + service identity metadata.
- AD itself is source of truth for directory state; the connector stores
  only coordination records, never passwords.

## Schedule

- Operation + audit stores: daily snapshot + pre-upgrade snapshot.
- Verify restore quarterly in the lab (restore → readiness → smoke).

## Restore procedure

1. Stop the service (prevents split-brain writes during restore).
2. Restore operation store first, then audit chain; verify chain integrity
   (tamper check must pass before start — a broken chain blocks startup).
3. Restore config/trust; run `scripts/validate_config.py`.
4. Start; confirm `/readiness` 200 and run the smoke matrix.
5. Reconcile in-flight operations: anything `EXECUTING` at backup time is
   re-driven by idempotency key on next delivery — safe by design.

## What NOT to restore

- Never restore an audit store over a newer one (destroys evidence).
- Never transplant stores across tenants/connectors (binding violation).
- Never back up secret material; rotate instead.
