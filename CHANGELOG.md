# Changelog

All notable changes to the MWA AD Connector. Format follows Keep a Changelog;
versioning follows SemVer (RC → pilot → GA, see `RELEASE.md`).

## [Unreleased]

### Added (Steps 16–17, API/transport/observability track)

- FastAPI app (`api/`): full §8.3 route surface (health, discovery, accounts,
  groups, OUs, operations/audit), central taxonomy error mapping, JWT +
  tenant/connector binding + scope dependencies, idempotency/ticket/
  correlation headers, middleware (correlation, 1 MiB payload limit,
  token-bucket rate limit, security headers), HMAC-signed page tokens,
  Prometheus `/metrics`.
- Outbound worker (`infrastructure/transport/`): `OutboundWorker` with
  envelope validation, binding checks, poison handling, idempotent dedup,
  redacted result publish, graceful shutdown; `InMemoryRelay`,
  `RelayTransport` protocol, `ServiceBusRelay` stub; backoff+jitter+budget
  retry; redacted DLQ store; `CanonicalDispatcherAdapter` bridge.
- Observability (`infrastructure/telemetry/`): redacted structlog JSON,
  SLA-neutral Prometheus metrics, optional OpenTelemetry tracing.
- Entrypoints: `mwa-api` (uvicorn) and `mwa-worker` (fail-closed without a
  wired dispatcher).
- Packaging: Windows Service (`install.ps1`, `service.xml`), conditional
  container image, config template + validation guide.
- Docs: capability catalog, API reference, runbook, incident response,
  backup/restore, troubleshooting, lab setup, authority matrix,
  implementation notes step-1…step-17.
- Tests: unit (taxonomy, states, policy, redaction, envelope, comparators,
  idempotency, transport/telemetry), gateway contract (fake + lab-gated
  real), lab placeholder matrix, fake e2e membership flow, security
  negatives (auth, binding, injection, limits, leakage).

### Fixed

- Error handler no longer crashes on validation errors with empty locations
  (fail-closed 400 instead of 500).
- Page-token decoder maps all malformed input to 400 (no codec leak to 500).

### Known limits

- `mwa-worker` requires the services-track dispatcher assembly
  (`OperationService.default_instance` or injected dispatcher).
- `bootstrap.create_app` still references the Step-1 skeleton factory name;
  use `api.app.create_app` / `entrypoints/*` (owning track to update).
- Real-AD suites skip without `MWA_AD_LAB=1` + lab DC.
