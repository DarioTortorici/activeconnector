"""Shared helpers for composition-runtime contract tests (no AD access)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mwa_ad_connector.api.dependencies import CallerContextFallback
from mwa_ad_connector.composition import build_runtime
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.infrastructure.persistence.audit_store import HashChainedAuditStore
from mwa_ad_connector.infrastructure.persistence.nonce_store import InMemoryNonceStore
from mwa_ad_connector.infrastructure.persistence.operation_store import InMemoryOperationStore
from tests.conftest import TEST_CONNECTOR_ID, TEST_CUSTOMER_ID, TEST_TENANT_ID
from tests.fakes.directory_gateway import FakeDirectoryGateway

BASE_DN = "DC=lab,DC=local"
MANAGED_OU = "OU=Managed,DC=lab,DC=local"
JWT_SECRET = "composition-jwt-secret"  # noqa: S105 - test-only canary.
PAGE_SECRET = "composition-page-secret"  # noqa: S105 - test-only canary.
BIND_SECRET = "composition-bind-secret"  # noqa: S105 - test-only canary.
RESET_SECRET = "Composition-Reset-Secret-1!"  # noqa: S105 - test-only canary.
MEMBER_SCOPES = ["ad.group.member.write", "ad.group.read"]
RESET_SCOPES = ["ad.account.password.reset", "ad.user.read"]


def make_connector_settings(tmp_path: Path, **overrides: Any) -> ConnectorSettings:
    """Build valid connector settings bound to a temporary state directory."""
    trust = tmp_path / "ca.pem"
    if not trust.exists():
        trust.write_text("fake-pem", encoding="utf-8")
    base: dict[str, Any] = {
        "customer_id": TEST_CUSTOMER_ID,
        "tenant_id": TEST_TENANT_ID,
        "connector_id": TEST_CONNECTOR_ID,
        "forest_id": "forest-lab",
        "domain_id": "domain-lab",
        "base_dn": BASE_DN,
        "managed_ous": [MANAGED_OU],
        "dc_host": "dc01.lab.local",
        "trust_store_path": str(trust),
        "auth_mode": "simple",
        "bind_user": "svc-mwa@lab.local",
        "bind_password": BIND_SECRET,
        "jwt_secret": JWT_SECRET,
        "page_token_secret": PAGE_SECRET,
        "validation_mode_only": False,
        "enable_password_reset": True,
        "state_dir": str(tmp_path / "state"),
    }
    base.update(overrides)
    return ConnectorSettings(**base)


def make_runtime(tmp_path: Path, gateway: Any | None = None, **overrides: Any) -> Any:
    """Build a runtime with an injected in-memory gateway and stores."""
    resolved_gateway = gateway if gateway is not None else FakeDirectoryGateway()
    settings = make_connector_settings(tmp_path, **overrides)
    return build_runtime(
        settings,
        gateway=resolved_gateway,
        operation_store=InMemoryOperationStore(),
        audit_store=HashChainedAuditStore(),
        nonce_store=InMemoryNonceStore(),
    )


def caller(scopes: list[str] | None = None, **overrides: Any) -> CallerContextFallback:
    """Build a canonical API caller context for direct service calls."""
    fields: dict[str, Any] = {
        "subject": "test-caller",
        "issuer": "mwa-trusted-agent",
        "audience": "mwa-ad-connector",
        "tenant_id": TEST_TENANT_ID,
        "customer_id": TEST_CUSTOMER_ID,
        "connector_id": TEST_CONNECTOR_ID,
        "scopes": list(scopes or []),
    }
    fields.update(overrides)
    return CallerContextFallback(**fields)


def approval() -> dict[str, str | list[str]]:
    """Build a fresh, policy-valid approval context."""
    return {
        "approval_id": "appr-composition-1",
        "approved_by": ["approver@lab.local"],
        "approved_at": datetime.now(UTC).isoformat(),
    }
