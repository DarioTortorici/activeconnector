"""API process entrypoint: load settings, wire the runtime, serve with uvicorn."""

from __future__ import annotations

import uvicorn

from mwa_ad_connector.api.app import create_app
from mwa_ad_connector.api.dependencies import RuntimeConfig
from mwa_ad_connector.composition import build_runtime
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.config.validation import validate_startup
from mwa_ad_connector.infrastructure.telemetry.logging import configure_logging, get_logger

logger = get_logger("entrypoint-api")


def _runtime_config(settings: ConnectorSettings) -> RuntimeConfig:
    """Map connector settings onto the API runtime config (secrets unwrapped)."""
    return RuntimeConfig(
        connector_id=settings.connector_id,
        tenant_id=settings.tenant_id,
        customer_id=settings.customer_id,
        api_host=settings.api_host,
        api_port=settings.api_port,
        payload_max_bytes=settings.request_max_bytes,
        rate_limit_capacity=settings.rate_limit_capacity,
        rate_limit_per_second=settings.rate_limit_per_second,
        jwt_issuer=settings.jwt_issuer,
        jwt_audience=settings.jwt_audience,
        jwt_secret=settings.jwt_secret.get_secret_value(),
        jwt_algorithms=tuple(settings.jwt_algorithms),
        jwt_clock_skew_seconds=settings.clock_skew_seconds,
        request_max_skew_seconds=settings.clock_skew_seconds,
        page_token_secret=settings.page_token_secret.get_secret_value(),
    )


def main() -> None:
    """Configure logging, wire the runtime, and serve the API with uvicorn."""
    configure_logging()
    settings = ConnectorSettings()
    validate_startup(settings)
    runtime = build_runtime(settings)
    logger.info("starting api", host=settings.api_host, port=settings.api_port, config=settings.model_dump_redacted())
    try:
        app = create_app(_runtime_config(settings), gateway=runtime.gateway, operation_service=runtime.api_service)
        uvicorn.run(app, host=settings.api_host, port=settings.api_port, log_level="info")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
