"""FastAPI application factory: routers, middleware, handlers, OpenAPI."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from mwa_ad_connector import __version__
from mwa_ad_connector.api import dependencies
from mwa_ad_connector.api.dependencies import RuntimeConfig, get_settings
from mwa_ad_connector.api.error_handlers import register_exception_handlers
from mwa_ad_connector.api.middleware.correlation import CorrelationMiddleware
from mwa_ad_connector.api.middleware.payload_limit import PayloadLimitMiddleware
from mwa_ad_connector.api.middleware.rate_limit import RateLimiter, RateLimitMiddleware
from mwa_ad_connector.api.middleware.security_headers import SecurityHeadersMiddleware
from mwa_ad_connector.api.routes import accounts, discovery, groups, health, operations, ous
from mwa_ad_connector.infrastructure.telemetry.metrics import ConnectorMetrics

_API_VERSION = "v1"


def create_app(
    settings: RuntimeConfig | None = None,
    *,
    gateway: Any | None = None,
    operation_service: Any | None = None,
) -> FastAPI:
    """Build the MWA AD Connector FastAPI application.

    Args:
        settings: Effective runtime config (loaded when omitted).
        gateway: Optional wired DirectoryGateway (composition runtime).
        operation_service: Optional wired OperationServicePort implementation.

    Returns:
        Configured FastAPI app mounted at /api/v1 (plus /metrics exposition).
    """
    resolved = settings or get_settings()
    app = FastAPI(
        title="MWA AD Connector",
        version=__version__,
        description=(
            "On-premises Active Directory connector (outbound-only). "
            "Capability allowlisted endpoints; no LDAP/PowerShell/shell passthrough."
        ),
        openapi_url=f"/api/{_API_VERSION}/openapi.json",
        docs_url=f"/api/{_API_VERSION}/docs",
        redoc_url=None,
    )
    app.state.settings = resolved
    app.state.metrics = ConnectorMetrics()

    if gateway is not None:
        app.dependency_overrides[dependencies.get_gateway] = lambda: gateway
    if operation_service is not None:
        app.dependency_overrides[dependencies.get_operation_service] = lambda: operation_service

    # Middleware order: correlation outermost so every response carries the id.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        limiter=RateLimiter(
            capacity=resolved.rate_limit_capacity,
            refill_per_second=resolved.rate_limit_per_second,
        ),
    )
    app.add_middleware(PayloadLimitMiddleware, max_bytes=resolved.payload_max_bytes)
    app.add_middleware(CorrelationMiddleware)

    register_exception_handlers(app)

    prefix = f"/api/{_API_VERSION}"
    app.include_router(health.router, prefix=prefix)
    app.include_router(discovery.router, prefix=prefix)
    app.include_router(accounts.router, prefix=prefix)
    app.include_router(groups.router, prefix=prefix)
    app.include_router(ous.router, prefix=prefix)
    app.include_router(operations.router, prefix=prefix)

    @app.get("/metrics", include_in_schema=False, summary="Prometheus exposition")
    async def metrics() -> PlainTextResponse:
        """Expose Prometheus text format (scrape endpoint, no auth in lab profile)."""
        body = app.state.metrics.exposition().decode("utf-8")
        return PlainTextResponse(body, media_type="text/plain; version=0.0.4")

    return app
