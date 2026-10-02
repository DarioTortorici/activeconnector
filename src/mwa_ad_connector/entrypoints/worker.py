"""Worker process entrypoint: outbound relay consumer with graceful shutdown.

The worker always runs the real runtime built by ``composition.build_runtime``;
the cloud relay is Service Bus only when explicitly enabled and configured,
otherwise the in-memory relay is used for lab/single-host operation. Assembly
faults are fail-closed: the process refuses to start rather than run unverified.
"""

from __future__ import annotations

import asyncio
import inspect
import signal
from contextlib import suppress
from typing import Any

from mwa_ad_connector.composition import build_runtime
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.infrastructure.telemetry.logging import configure_logging, get_logger
from mwa_ad_connector.infrastructure.transport.relay import InMemoryRelay, ServiceBusRelay
from mwa_ad_connector.infrastructure.transport.worker import OperationServiceDispatcher, OutboundWorker, WorkerConfig

logger = get_logger("entrypoint-worker")


def get_settings() -> ConnectorSettings:
    """Load validated connector settings from the environment (fail-fast)."""
    return ConnectorSettings()


def _build_relay(settings: ConnectorSettings | None = None) -> InMemoryRelay | ServiceBusRelay:
    """Select the relay from settings (Service Bus when enabled, in-memory otherwise)."""
    resolved = settings if settings is not None else get_settings()
    connection_string = (
        resolved.servicebus_connection_string.get_secret_value() if resolved.servicebus_connection_string else ""
    )
    if resolved.servicebus_enabled and connection_string:
        logger.info("using ServiceBusRelay", result_queue=resolved.servicebus_result_queue)
        return ServiceBusRelay(
            connection_string=connection_string,
            command_queue=resolved.servicebus_command_queue,
            result_queue=resolved.servicebus_result_queue,
        )
    return InMemoryRelay()


def _build_dispatcher(settings: ConnectorSettings | None = None) -> OperationServiceDispatcher:
    """Build the dispatcher over the real runtime assembly (fail-closed)."""
    resolved = settings if settings is not None else get_settings()
    try:
        runtime = build_runtime(resolved)
        return OperationServiceDispatcher(runtime.api_service)
    except Exception as exc:
        raise RuntimeError(
            "No operation service is wired: the runtime assembly failed. Refusing to start (fail-closed)."
        ) from exc


async def _close_relay(relay: Any) -> None:  # noqa: ANN401 - any RelayTransport implementation.
    """Close the relay if it exposes a ``close`` (async or sync), best effort."""
    closer = getattr(relay, "close", None)
    if not callable(closer):
        return
    with suppress(Exception):
        outcome = closer()
        if inspect.isawaitable(outcome):
            await outcome


async def _run() -> None:
    """Run the worker until SIGINT/SIGTERM (graceful: in-flight message completes)."""
    settings = get_settings()
    relay = _build_relay(settings)
    worker = OutboundWorker(
        relay,
        _build_dispatcher(settings),
        WorkerConfig(expected_tenant_id=settings.tenant_id, expected_connector_id=settings.connector_id),
    )
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):  # Windows event loop policy lacks add_signal_handler.
            loop.add_signal_handler(sig, worker.stop)
    logger.info("starting worker", connector_id=settings.connector_id, tenant_id=settings.tenant_id)
    try:
        await worker.run()
    finally:
        await _close_relay(relay)


def main() -> None:
    """Configure logging and run the worker event loop."""
    configure_logging()
    asyncio.run(_run())


if __name__ == "__main__":
    main()
