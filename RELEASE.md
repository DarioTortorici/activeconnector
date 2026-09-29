# Release process (Step 22: RC → pilot → rollback)

## Versioning

SemVer. Release branches `release/vX.Y.Z-rc.N`; tags signed; SBOM +
dependency/security scans attached to every RC.

## RC checklist

- [ ] `uv sync --frozen --all-groups` clean on a fresh clone.
- [ ] `ruff format --check`, `ruff check`, `mypy src tests` green.
- [ ] `pytest` green; new-code coverage ≥ 80% (≥ 90% critical modules).
- [ ] Lab matrix green on an isolated DC (see `docs/laboratory/lab-setup.md`).
- [ ] Secret scan green (no credentials in repo, logs, fixtures, exports).
- [ ] `docs/operations/runbook.md` owner + on-call named.

## Pilot

1. Deploy RC to the pilot connector (allowlisted customer/tenant only).
2. Smoke: health → readiness → resolve → search → unlock dry-run.
3. Soak 1 week: watch `mwa_verification_failures_total`, DLQ depth,
   `mwa_api_errors_total` by code; zero `FAILED_VERIFICATION` unexplained.
4. CAB + security + product sign-off before wider rollout.

## Rollout / rollback

- Roll forward in waves; keep the previous artifact + store snapshots.
- Rollback: stop → restore artifact/config (audit is append-only, never
  restored over) → validate config → start → readiness + smoke.
- Never roll back to bypass an `APPROVAL_REQUIRED`/`PROTECTED_TARGET`
  denial — those are controls, not bugs.
