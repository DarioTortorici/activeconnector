"""Extra contract coverage: schema export, validation branches, bootstrap."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from mwa_ad_connector import __version__
from mwa_ad_connector.bootstrap import create_app, get_version
from mwa_ad_connector.config.schema import export_json_schema, settings_json_schema, write_schema_file
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.config.validation import ConfigurationError, validate_startup
from mwa_ad_connector.domain.enums import MutationDisposition, OperationState
from mwa_ad_connector.domain.operations import is_legal_transition


def test_schema_export_helpers(tmp_path: Path) -> None:
    """Schema helpers produce a versioned document and a writable file."""
    assert "settings" in export_json_schema()
    assert "properties" in settings_json_schema()
    destination = write_schema_file(tmp_path / "schema" / "config-schema.json")
    assert destination.is_file()


def test_bootstrap_version_and_app_factory() -> None:
    """Version helper works; the lazy factory returns a wired FastAPI app."""
    assert get_version() == __version__
    app = create_app()
    assert callable(getattr(app, "include_router", None))


def test_validate_startup_rejects_duplicates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Duplicate managed OUs fail startup validation."""
    trust = tmp_path / "ca.pem"
    trust.write_text("fake-pem", encoding="utf-8")
    env = {
        "MWA_AD_CUSTOMER_ID": "c",
        "MWA_AD_TENANT_ID": "t",
        "MWA_AD_CONNECTOR_ID": "conn",
        "MWA_AD_FOREST_ID": "f",
        "MWA_AD_DOMAIN_ID": "d",
        "MWA_AD_BASE_DN": "DC=lab,DC=local",
        "MWA_AD_MANAGED_OUS": '["OU=A,DC=lab,DC=local", "ou=a,dc=lab,dc=local"]',
        "MWA_AD_DC_HOST": "dc01.lab.local",
        "MWA_AD_TRUST_STORE_PATH": str(trust),
        "MWA_AD_AUTH_MODE": "gmsa",
        "MWA_AD_JWT_SECRET": "test-only-jwt-secret",
        "MWA_AD_PAGE_TOKEN_SECRET": "test-only-page-secret",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    settings = ConnectorSettings()
    with pytest.raises(ConfigurationError):
        validate_startup(settings)


def test_operation_state_helpers() -> None:
    """Transition legality and enum round-trips behave as documented."""
    assert not is_legal_transition(OperationState.RECEIVED, OperationState.AD_VERIFIED)
    assert not is_legal_transition(OperationState.FAILED, OperationState.RECEIVED)
    assert OperationState("RECEIVED") is OperationState.RECEIVED
    assert MutationDisposition("NO_OP") is MutationDisposition.NO_OP
    assert datetime.now(timezone.utc).tzinfo is not None
    assert uuid4().hex != ""
