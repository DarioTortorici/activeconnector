"""Unit tests for Service Bus settings (defaults, redaction, fail-fast)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mwa_ad_connector.config.settings import ConnectorSettings

CONNECTION_STRING = "Endpoint=sb://unit.test/;SharedAccessKeyName=k;SharedAccessKey=se=cret"


def _settings(**overrides: Any) -> ConnectorSettings:
    """Build minimal valid settings with Service Bus overrides."""
    base: dict[str, Any] = {
        "customer_id": "customer-lab",
        "tenant_id": "tenant-lab",
        "connector_id": "connector-lab-01",
        "forest_id": "forest-lab",
        "domain_id": "domain-lab",
        "base_dn": "DC=lab,DC=local",
        "managed_ous": ["OU=Users,DC=lab,DC=local"],
        "dc_host": "dc01.lab.local",
        "auth_mode": "gmsa",
        "jwt_secret": "test-only-jwt-secret",
        "page_token_secret": "test-only-page-secret",
    }
    base.update(overrides)
    return ConnectorSettings(**base)


def test_servicebus_defaults() -> None:
    """Service Bus is disabled by default with the standard queue names."""
    settings = _settings()

    assert settings.servicebus_enabled is False
    assert settings.servicebus_connection_string is None
    assert settings.servicebus_command_queue == "ad-commands"
    assert settings.servicebus_result_queue == "ad-results"


def test_servicebus_connection_string_is_redacted() -> None:
    """The connection string never appears in the redacted dump."""
    settings = _settings(servicebus_connection_string=CONNECTION_STRING)

    dumped = settings.model_dump_redacted()

    assert dumped["servicebus_connection_string"] == "***REDACTED***"
    assert CONNECTION_STRING not in str(dumped)


def test_servicebus_enabled_requires_connection_string() -> None:
    """Enabling the relay without credentials fails fast."""
    with pytest.raises(ValidationError):
        _settings(servicebus_enabled=True)


def test_servicebus_enabled_with_connection_string_is_valid() -> None:
    """Enabling the relay with credentials validates and keeps the queues."""
    settings = _settings(servicebus_enabled=True, servicebus_connection_string=CONNECTION_STRING)

    assert settings.servicebus_enabled is True
    assert settings.servicebus_connection_string is not None
    assert settings.servicebus_connection_string.get_secret_value() == CONNECTION_STRING
