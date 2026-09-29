"""Fail-fast startup validation for connector configuration."""

from __future__ import annotations

import logging
from pathlib import Path

from mwa_ad_connector.config.settings import ConnectorSettings

logger = logging.getLogger(__name__)


class ConfigurationError(ValueError):
    """Raised when startup configuration is missing or incoherent."""


def validate_startup(settings: ConnectorSettings) -> None:
    """Validate settings before any network bind or store access.

    Checks duplicate/empty OU scopes, trust-store readability when LDAPS
    validation is enforced, and dangerous flag combinations.

    Args:
        settings: Loaded connector settings.

    Raises:
        ConfigurationError: On any fail-fast violation.
    """
    seen: set[str] = set()
    for ou in settings.managed_ous:
        normalized = ou.strip().lower()
        if not normalized:
            raise ConfigurationError("managed_ous contains an empty DN")
        if normalized in seen:
            raise ConfigurationError(f"duplicate managed OU: {ou}")
        seen.add(normalized)

    if settings.use_ldaps and settings.ldaps_require_cert:
        if not settings.trust_store_path:
            raise ConfigurationError("trust_store_path is required when ldaps_require_cert=true")
        trust_path = Path(settings.trust_store_path)
        if not trust_path.is_file():
            raise ConfigurationError(f"trust store not readable: {settings.trust_store_path}")

    if settings.validation_mode_only and settings.enable_password_reset:
        logger.warning("password reset enabled while validation_mode_only=true; preflight will force dry-run")

    logger.info(
        "configuration_valid",
        extra={
            "connector_id": settings.connector_id,
            "domain_id": settings.domain_id,
            "auth_mode": settings.auth_mode,
        },
    )
