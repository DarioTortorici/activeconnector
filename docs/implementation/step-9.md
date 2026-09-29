# Step 9 — Operation store, idempotency, audit

Atomic transitions, `(tenant, connector, key)` uniqueness with collision on
payload change, before/requested/after audit with tamper evidence. Owner:
operations track. API surfaces: `Idempotency-Key` enforcement, operation/audit
routes (`api/routes/operations.py`), in-worker dedup cache. Tests:
`tests/unit/test_idempotency.py`, worker e2e.
