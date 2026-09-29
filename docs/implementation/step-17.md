# Step 17 — Health, readiness, observability, API (this track)

- `api/app.py:create_app` — FastAPI `MWA AD Connector` at `/api/v1` with
  routers, middleware (correlation/payload/rate/security-headers), central
  exception handlers, OpenAPI; `/metrics` Prometheus exposition.
- `api/routes/*` — full §8.3 surface, HTTP semantics §3.5
  (200 verified / 202 queued+status_url / 502 FAILED_VERIFICATION+evidence).
- `api/dependencies.py` — JWT + tenant/connector binding + scopes,
  idempotency/ticket/correlation headers, gateway/service seams.
- `api/error_handlers.py` — taxonomy mapping (never raw LDAP text).
- `infrastructure/telemetry/` — structlog JSON with redaction processor,
  SLA-neutral Prometheus metrics, optional OTel tracing.
- `GET /health` anonymous redacted; `GET /readiness` scoped, 200/503.
