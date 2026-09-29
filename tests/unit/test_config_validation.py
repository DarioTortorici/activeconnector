"""Unit tests for secure configuration fail-fast behavior (Step 4)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mwa_ad_connector.config.profiles import ConnectorProfile, DomainProfile, ForestProfile
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.config.validation import ConfigurationError, validate_startup


def _base_env(tmp_path: Path) -> dict[str, str]:
    """Build a minimal valid environment mapping."""
    trust = tmp_path / "ca.pem"
    trust.write_text("fake-pem", encoding="utf-8")
    return {
        "MWA_AD_CUSTOMER_ID": "customer-lab",
        "MWA_AD_TENANT_ID": "tenant-lab",
        "MWA_AD_CONNECTOR_ID": "connector-lab-01",
        "MWA_AD_FOREST_ID": "forest-lab",
        "MWA_AD_DOMAIN_ID": "domain-lab",
        "MWA_AD_BASE_DN": "DC=lab,DC=local",
        "MWA_AD_MANAGED_OUS": '["OU=Users,DC=lab,DC=local"]',
        "MWA_AD_DC_HOST": "dc01.lab.local",
        "MWA_AD_TRUST_STORE_PATH": str(trust),
        "MWA_AD_AUTH_MODE": "gmsa",
        "MWA_AD_JWT_SECRET": "test-only-jwt-secret",
        "MWA_AD_PAGE_TOKEN_SECRET": "test-only-page-secret",
    }


def test_managed_ou_outside_base_dn_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """OUs outside the base DN fail fast at settings load."""
    for key, value in _base_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("MWA_AD_MANAGED_OUS", '["OU=Evil,DC=other,DC=local"]')
    with pytest.raises(ValidationError):
        ConnectorSettings()


def test_password_reset_requires_ldaps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Password reset without LDAPS is rejected."""
    for key, value in _base_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("MWA_AD_USE_LDAPS", "false")
    monkeypatch.setenv("MWA_AD_ENABLE_PASSWORD_RESET", "true")
    with pytest.raises(ValidationError):
        ConnectorSettings()


def test_validate_startup_rejects_missing_trust_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing trust bundle fails startup validation."""
    for key, value in _base_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("MWA_AD_TRUST_STORE_PATH", str(tmp_path / "missing.pem"))
    settings = ConnectorSettings()
    with pytest.raises(ConfigurationError):
        validate_startup(settings)


def test_validate_startup_ok_and_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Valid settings pass and redact secrets/hosts on dump."""
    for key, value in _base_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    settings = ConnectorSettings()
    validate_startup(settings)
    dumped = settings.model_dump_redacted()
    assert dumped["dc_host"] == "***REDACTED***"


def test_connector_profile_domain_lookup() -> None:
    """Connector profiles resolve served domain ids."""
    domain = DomainProfile(
        domain_id="domain-lab",
        forest_id="forest-lab",
        base_dn="DC=lab,DC=local",
        managed_ous=["OU=Users,DC=lab,DC=local"],
    )
    profile = ConnectorProfile(
        customer_id="c",
        tenant_id="t",
        connector_id="conn",
        forests=[ForestProfile(forest_id="forest-lab", domains=[domain])],
    )
    assert profile.domain_ids() == ["domain-lab"]
    assert profile.find_domain("domain-lab") == domain
    assert profile.find_domain("unknown") is None
