"""Application bootstrap factory.

This module is intentionally thin: it lazily imports the FastAPI
application (owned by a later step) so that domain, application and
config layers never import web frameworks at module load time.

Why lazy import: keeps ``bootstrap`` importable in unit/contract
tests and on hosts without API dependencies installed, while still
providing a single documented entrypoint for servers/workers.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

from mwa_ad_connector import __version__

logger = logging.getLogger(__name__)


def create_app() -> Any:
    """Create and return the FastAPI application instance.

    Returns:
        The FastAPI application object built by ``mwa_ad_connector.api.app``.

    Raises:
        ImportError: If the API layer is unavailable.
    """
    try:
        module: Any = importlib.import_module("mwa_ad_connector.api.app")
        factory: Any = module.create_app
    except (ImportError, AttributeError) as exc:
        logger.error("api_layer_missing", extra={"error": str(exc)})
        raise ImportError(
            "API layer unavailable (mwa_ad_connector.api.app.create_app); install the API dependencies."
        ) from exc
    app: Any = factory()
    logger.info("app_created")
    return app


def get_version() -> str:
    """Return the connector package version.

    Returns:
        Semantic version string.
    """
    return __version__
