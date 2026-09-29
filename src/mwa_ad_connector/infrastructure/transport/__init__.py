"""Outbound-only transport: worker, relay abstraction, retry, dead-letter queue."""

from mwa_ad_connector.infrastructure.transport.dead_letter import DeadLetterRecord, InMemoryDeadLetterStore
from mwa_ad_connector.infrastructure.transport.relay import InMemoryRelay, RelayMessage, RelayTransport, ServiceBusRelay
from mwa_ad_connector.infrastructure.transport.retry import RetryBudget, RetryPolicy, compute_backoff_delay
from mwa_ad_connector.infrastructure.transport.worker import (
    CanonicalDispatcherAdapter,
    OutboundWorker,
    WorkerConfig,
)

__all__ = [
    "CanonicalDispatcherAdapter",
    "DeadLetterRecord",
    "InMemoryDeadLetterStore",
    "InMemoryRelay",
    "OutboundWorker",
    "RelayMessage",
    "RelayTransport",
    "RetryBudget",
    "RetryPolicy",
    "ServiceBusRelay",
    "WorkerConfig",
    "compute_backoff_delay",
]
