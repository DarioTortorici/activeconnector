"""Configuration package public surface."""

from __future__ import annotations

from mwa_ad_connector.config.profiles import ConnectorProfile, DomainProfile, ForestProfile
from mwa_ad_connector.config.schema import export_json_schema, settings_json_schema, write_schema_file
from mwa_ad_connector.config.settings import AuthMode, ConnectorSettings, SourceAnchorStrategy
from mwa_ad_connector.config.validation import ConfigurationError, validate_startup

__all__ = [
    "AuthMode",
    "ConfigurationError",
    "ConnectorProfile",
    "ConnectorSettings",
    "DomainProfile",
    "ForestProfile",
    "SourceAnchorStrategy",
    "export_json_schema",
    "settings_json_schema",
    "validate_startup",
    "write_schema_file",
]
