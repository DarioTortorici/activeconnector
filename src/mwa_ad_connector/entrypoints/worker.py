"""Worker process entrypoint: outbound relay consumer with graceful shutdown."""

from __future__ import annotations

import asyncio
import os
import signal
from contextlib import suppress

from mwa_ad_connector.api.dependencies import get_settings
from mwa_ad_connector.infrastructure.telemetry.logging import configure_logging, get_logger
from mwa_ad_connector.infrastructure.transport.relay import InMemoryRelay, ServiceBusRelay
from mwa_ad_connector.infrastructure.transport.worker import OperationServiceDispatcher, OutboundWorker, WorkerConfig

try:  # Optional services track: hard dependency only when running the worker process.
    from mwa_ad_connector.application.services.operation_service import OperationService
except ImportError:
    OperationService = None  # type: ignore[assignment, misc]

logger = get_logger("entrypoint-worker")


def _build_relay() -> InMemoryRelay | ServiceBusRelay:
    """Select the relay: Service Bus stub when configured, in-memory otherwise."""
    namespace = os.environ.get("MWA_RELAY_NAMESPACE", "")
    queue = os.environ.get("MWA_RELAY_QUEUE", "")
    if namespace and queue:
        logger.info("using ServiceBusRelay stub (wiring lands with cloud integration)")
        return ServiceBusRelay(fully_qualified_namespace=namespace, queue_name=queue)
    return InMemoryRelay()


def _build_dispatcher() -> OperationServiceDispatcher:
    """Build the dispatcher over the canonical operation service when available."""
    if OperationService is None:
        raise RuntimeError(
            "No operation service is wired: the services track has not landed. Refusing to start (fail-closed)."
        )
    factory = getattr(OperationService, "default_instance", None)
    if not callable(factory):
        raise RuntimeError("OperationService exposes no default_instance assembly: refusing to start (fail-closed).")
    try:
        return OperationServiceDispatcher(factory())
    except Exception as exc:
        raise RuntimeError(
            "No operation service is wired: the services track assembly failed. Refusing to start (fail-closed)."
        ) from exc


async def _run() -> None:
    """Run the worker until SIGINT/SIGTERM (graceful: in-flight message completes)."""
    settings = get_settings()
    relay = _build_relay()
    worker = OutboundWorker(
        relay,
        _build_dispatcher(),
        WorkerConfig(expected_tenant_id=settings.tenant_id, expected_connector_id=settings.connector_id),
    )
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):  # Windows event loop policy lacks add_signal_handler.
            loop.add_signal_handler(sig, worker.stop)
    logger.info("starting worker", connector_id=settings.connector_id, tenant_id=settings.tenant_id)
    await worker.run()


def main() -> None:
    """Configure logging and run the worker event loop."""
    configure_logging()
    asyncio.run(_run())


if __name__ == "__main__":
    main()
