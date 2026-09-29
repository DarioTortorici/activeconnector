# Runbook (Step 21)

## Start / stop

```powershell
Start-Service MWAADConnector   # API + worker under WinSW supervision
Stop-Service MWAADConnector    # graceful: in-flight message completes first
```

## Daily checks

1. `GET /api/v1/health` → `HEALTHY` (anonymous).
2. `GET /api/v1/readiness` (token) → `ready: true`; investigate any
   `healthy: false` check before approving mutations.
3. Scrape `/metrics`: `mwa_operations_total`, `mwa_verification_failures_total`,
   `mwa_worker_messages_total{outcome}`, `mwa_api_errors_total{code}`.
4. DLQ depth (`dead_lettered` counter / store count): any record needs
   operator triage — never blindly requeue poison messages.

## Deploy / upgrade

1. Snapshot/backup operation + audit stores (see `backup-restore.md`).
2. Stop service, deploy artifact, run `scripts/validate_config.py`.
3. Start, verify health/readiness, run smoke: resolve → search → unlock dry-run.
4. Pilot allowlist first; general rollout only after pilot sign-off.

## Rollback

1. Stop service, restore previous artifact + config.
2. Restore stores only if the migration guide says so (idempotency keys make
   re-execution safe; audit is append-only and never rolled back).
3. Verify health/readiness + smoke, then re-enable traffic.

## Log triage

Structured JSON logs carry `timestamp/ticket/component/severity/result/
correlation_id`. Secrets are redacted at emission — if a secret ever appears,
treat as a security incident (see `incident-response.md`), not a log bug.
