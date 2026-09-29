# Step 16 — Outbound worker & transport (this track)

`infrastructure/transport/`: `OutboundWorker` (receive → canonical/local
envelope validate → tenant/connector binding → poison check → dedup →
dispatch → redacted publish → ack; graceful stop), `InMemoryRelay` +
`RelayTransport` protocol + `ServiceBusRelay` stub (swappable, SDK-free core),
`RetryPolicy` (exp backoff + jitter + budget, dependency-only retryability),
DLQ store with redacted poison records. Canonical bridge:
`CanonicalDispatcherAdapter`. Entrypoint: `entrypoints/worker.py`
(fail-closed without a wired dispatcher). Tests: e2e membership flow,
duplicate-delivery, malformed/misbound quarantine, graceful stop.
