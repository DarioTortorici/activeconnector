"""Unit: optional TLS/mTLS on the API entrypoint (settings + uvicorn wiring)."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import mwa_ad_connector.entrypoints.api as api_entry
from mwa_ad_connector.config.settings import ConnectorSettings

BASE: dict[str, Any] = {
    "customer_id": "customer-lab",
    "tenant_id": "tenant-lab",
    "connector_id": "connector-lab-01",
    "forest_id": "forest-lab",
    "domain_id": "domain-lab",
    "base_dn": "DC=lab,DC=local",
    "managed_ous": ["OU=Users,DC=lab,DC=local"],
    "dc_host": "dc01.lab.local",
    "auth_mode": "simple",
    "bind_user": "svc-mwa@lab.local",
    "bind_password": "test-only-bind-secret",
    "jwt_secret": "test-only-jwt-secret",
    "page_token_secret": "test-only-page-secret",
}


def _settings(**overrides: Any) -> ConnectorSettings:
    values = dict(BASE)
    values.update(overrides)
    return ConnectorSettings(**values)


def test_tls_disabled_by_default() -> None:
    settings = _settings()
    assert settings.tls_enabled is False
    assert settings.tls_require_client_cert is False


def test_tls_enabled_requires_cert_and_key() -> None:
    with pytest.raises(ValidationError):
        _settings(tls_enabled=True)
    with pytest.raises(ValidationError):
        _settings(tls_enabled=True, tls_certfile="c.pem")


def test_mtls_requires_ca_bundle() -> None:
    with pytest.raises(ValidationError):
        _settings(tls_enabled=True, tls_certfile="c.pem", tls_keyfile="k.pem", tls_require_client_cert=True)
    settings = _settings(
        tls_enabled=True,
        tls_certfile="c.pem",
        tls_keyfile="k.pem",
        tls_ca_certs="ca.pem",
        tls_require_client_cert=True,
    )
    assert settings.tls_require_client_cert is True


def _run_entrypoint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **env: str) -> dict[str, Any]:
    trust = tmp_path / "ca.pem"
    trust.write_text("fake-pem", encoding="utf-8")
    environment = {
        "MWA_AD_CUSTOMER_ID": "customer-lab",
        "MWA_AD_TENANT_ID": "tenant-lab",
        "MWA_AD_CONNECTOR_ID": "connector-lab-01",
        "MWA_AD_FOREST_ID": "forest-lab",
        "MWA_AD_DOMAIN_ID": "domain-lab",
        "MWA_AD_BASE_DN": "DC=lab,DC=local",
        "MWA_AD_MANAGED_OUS": '["OU=Managed,DC=lab,DC=local"]',
        "MWA_AD_DC_HOST": "dc01.lab.local",
        "MWA_AD_TRUST_STORE_PATH": str(trust),
        "MWA_AD_AUTH_MODE": "simple",
        "MWA_AD_BIND_USER": "svc-mwa@lab.local",
        "MWA_AD_BIND_PASSWORD": "test-only-bind-secret",
        "MWA_AD_JWT_SECRET": "test-only-jwt-secret",
        "MWA_AD_PAGE_TOKEN_SECRET": "test-only-page-secret",
        "MWA_AD_STATE_DIR": str(tmp_path / "state"),
    }
    environment.update(env)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    launched: dict[str, Any] = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: launched.update(app=app, **kwargs))
    api_entry.main()
    return launched


def test_entrypoint_http_by_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    launched = _run_entrypoint(monkeypatch, tmp_path)
    assert launched["host"] == "127.0.0.1" and launched["port"] == 8443
    assert "ssl_certfile" not in launched


def test_entrypoint_tls_wired_when_enabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    launched = _run_entrypoint(
        monkeypatch,
        tmp_path,
        MWA_AD_TLS_ENABLED="true",
        MWA_AD_TLS_CERTFILE="server.crt",
        MWA_AD_TLS_KEYFILE="server.key",
    )
    assert launched["ssl_certfile"] == "server.crt"
    assert launched["ssl_keyfile"] == "server.key"
    assert launched["ssl_cert_reqs"] == ssl.CERT_NONE


def test_entrypoint_mtls_sets_cert_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    launched = _run_entrypoint(
        monkeypatch,
        tmp_path,
        MWA_AD_TLS_ENABLED="true",
        MWA_AD_TLS_CERTFILE="server.crt",
        MWA_AD_TLS_KEYFILE="server.key",
        MWA_AD_TLS_CA_CERTS="ca.pem",
        MWA_AD_TLS_REQUIRE_CLIENT_CERT="true",
    )
    assert launched["ssl_ca_certs"] == "ca.pem"
    assert launched["ssl_cert_reqs"] == ssl.CERT_REQUIRED
