"""Prometheus metrics (SLA-neutral: raw counts/latencies, no hardcoded SLO thresholds)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

OPERATION_BUCKETS: tuple[float, ...] = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


class ConnectorMetrics:
    """Connector metrics bound to a private registry (safe for tests and reloads).

    Counters:
        operations_total{capability,state}: completed capability executions.
        verification_failures_total{capability}: read-after-write mismatches.
        worker_messages_total{outcome}: received/acked/dead-lettered transport messages.
        api_errors_total{code}: mapped API errors by stable domain code.
    Histogram:
        operation_latency_seconds{capability}: end-to-end execution latency.
    """

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        """Create metrics on the given (or a fresh) Prometheus registry."""
        self.registry = registry or CollectorRegistry()
        self.operations_total = Counter(
            "mwa_operations_total",
            "Completed capability executions by capability and terminal state.",
            ["capability", "state"],
            registry=self.registry,
        )
        self.verification_failures_total = Counter(
            "mwa_verification_failures_total",
            "Read-after-write verification failures by capability.",
            ["capability"],
            registry=self.registry,
        )
        self.worker_messages_total = Counter(
            "mwa_worker_messages_total",
            "Transport messages handled by the outbound worker by outcome.",
            ["outcome"],
            registry=self.registry,
        )
        self.api_errors_total = Counter(
            "mwa_api_errors_total",
            "Mapped API errors by stable domain code.",
            ["code"],
            registry=self.registry,
        )
        self.operation_latency = Histogram(
            "mwa_operation_latency_seconds",
            "End-to-end capability execution latency in seconds.",
            ["capability"],
            buckets=OPERATION_BUCKETS,
            registry=self.registry,
        )

    def observe_operation(self, *, capability: str, state: str, latency_seconds: float) -> None:
        """Record one finished capability execution.

        Args:
            capability: Stable capability id (e.g. "group.member.add").
            state: Terminal operation state (e.g. "AD_VERIFIED").
            latency_seconds: Wall-clock duration, must be >= 0.
        """
        self.operations_total.labels(capability=capability, state=state).inc()
        self.operation_latency.labels(capability=capability).observe(max(0.0, latency_seconds))

    def inc_verification_failure(self, *, capability: str) -> None:
        """Count one FAILED_VERIFICATION outcome for a capability."""
        self.verification_failures_total.labels(capability=capability).inc()

    def inc_worker_message(self, *, outcome: str) -> None:
        """Count one transport message outcome (received/acked/retried/dead_lettered).

        Args:
            outcome: One of received, acked, retried, dead_lettered, poison.
        """
        self.worker_messages_total.labels(outcome=outcome).inc()

    def inc_api_error(self, *, code: str) -> None:
        """Count one mapped API error by stable domain code."""
        self.api_errors_total.labels(code=code).inc()

    def exposition(self) -> bytes:
        """Render Prometheus text exposition format for this registry."""
        return generate_latest(self.registry)
