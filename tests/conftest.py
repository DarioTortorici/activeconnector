"""Shared fixtures: test settings, JWT auth headers, fake gateway/service, TestClient."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient

from mwa_ad_connector.api import dependencies as deps
from mwa_ad_connector.api.app import create_app
from mwa_ad_connector.api.dependencies import RuntimeConfig
from mwa_ad_connector.api.error_handlers import ConnectorError
from mwa_ad_connector.api.schemas.groups import GROUP_WRITABLE_ATTRIBUTES
from mwa_ad_connector.api.schemas.users import USER_WRITABLE_ATTRIBUTES

TEST_CONNECTOR_ID = "connector-lab-01"
TEST_TENANT_ID = "tenant-lab"
TEST_CUSTOMER_ID = "customer-lab"
TEST_JWT_SECRET = "test-only-jwt-secret"  # noqa: S105 - test-only HMAC key, never production.
TEST_PAGE_SECRET = "test-only-page-secret"  # noqa: S105 - test-only HMAC key, never production.
ALL_SCOPES = [
    "ad.health.read",
    "ad.readiness.read",
    "ad.discovery.read",
    "ad.user.read",
    "ad.group.read",
    "ad.group.members.read",
    "ad.group.member.write",
    "ad.account.unlock",
    "ad.account.password.reset",
    "ad.account.password.force_change",
    "ad.account.state.write",
    "ad.user.attributes.write",
    "ad.user.lifecycle.write",
    "ad.user.create",
    "ad.user.delete",
    "ad.group.create",
    "ad.group.attributes.write",
    "ad.group.rename",
    "ad.group.move",
    "ad.group.delete",
    "ad.ou.create",
    "ad.ou.rename",
    "ad.ou.move",
    "ad.ou.delete",
    "ad.operation.read",
    "ad.audit.read",
    "ad.audit.export",
]

NOT_FOUND_GUID = "00000000-0000-0000-0000-000000000000"
PROTECTED_GUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
OUT_OF_SCOPE_GUID = "22222222-2222-2222-2222-222222222222"
APPROVAL_GUID = "33333333-3333-3333-3333-333333333333"
COLLISION_GUID = "44444444-4444-4444-4444-444444444444"
CONCURRENT_GUID = "55555555-5555-5555-5555-555555555555"
LDAP_DOWN_GUID = "66666666-6666-6666-6666-666666666666"
FAILED_VERIFY_GUID = "77777777-7777-7777-7777-777777777777"
QUEUED_GUID = "88888888-8888-8888-8888-888888888888"


def make_settings(**overrides: Any) -> RuntimeConfig:
    """Build test runtime config with safe test-only secrets."""
    base: dict[str, Any] = {
        "connector_id": TEST_CONNECTOR_ID,
        "tenant_id": TEST_TENANT_ID,
        "customer_id": TEST_CUSTOMER_ID,
        "jwt_secret": TEST_JWT_SECRET,
        "page_token_secret": TEST_PAGE_SECRET,
    }
    base.update(overrides)
    return RuntimeConfig(**base)


def make_token(
    settings: RuntimeConfig,
    scopes: list[str] | None = None,
    tenant_id: str | None = None,
    expired: bool = False,
    wrong_audience: bool = False,
) -> str:
    """Mint a test caller JWT (HS256, test secret only)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "test-caller",
        "iss": settings.jwt_issuer,
        "aud": "wrong-audience" if wrong_audience else settings.jwt_audience,
        "exp": now - timedelta(minutes=5) if expired else now + timedelta(minutes=5),
        "iat": now,
        "jti": uuid.uuid4().hex,
        "tenant_id": TEST_TENANT_ID if tenant_id is None else tenant_id,
        "customer_id": TEST_CUSTOMER_ID,
        "connector_id": TEST_CONNECTOR_ID,
        "scopes": ALL_SCOPES if scopes is None else scopes,
        "roles": ["operator"],
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def auth_headers(
    settings: RuntimeConfig,
    scopes: list[str] | None = None,
    tenant_id: str | None = None,
    include_idempotency: bool = True,
    include_ticket: bool = True,
    **token_kwargs: Any,
) -> dict[str, str]:
    """Build the full mandatory header set for an authenticated request."""
    headers = {
        "Authorization": f"Bearer {make_token(settings, scopes, tenant_id, **token_kwargs)}",
        "X-Tenant-ID": TEST_TENANT_ID if tenant_id is None else tenant_id,
        "X-Connector-ID": settings.connector_id,
        "X-Request-Timestamp": datetime.now(timezone.utc).isoformat(),
        "X-Request-Nonce": uuid.uuid4().hex,
        "X-Correlation-ID": uuid.uuid4().hex,
    }
    if include_idempotency:
        headers["Idempotency-Key"] = uuid.uuid4().hex
    if include_ticket:
        headers["X-Ticket-ID"] = "TICKET-123"
    return headers


def make_envelope(**overrides: Any) -> dict[str, Any]:
    """Build a valid §8.4-shaped command envelope for worker tests.

    Includes the canonical target scope (domain_id/forest_id) and requested_by
    so it validates against both the canonical CommandEnvelope and the local
    worker fallback; parameters stay within the per-capability allowlist.
    """
    now = datetime.now(timezone.utc)
    envelope: dict[str, Any] = {
        "schema_version": "1.0",
        "capability": "group.member.add",
        "customer_id": TEST_CUSTOMER_ID,
        "tenant_id": TEST_TENANT_ID,
        "connector_id": TEST_CONNECTOR_ID,
        "forest_id": "forest-lab",
        "domain_id": "domain-lab",
        "target": {
            "object_type": "GROUP",
            "object_guid": "7e565f72-8274-4cb8-b77a-7dad17a1b432",
            "domain_id": "domain-lab",
            "forest_id": "forest-lab",
        },
        "parameters": {"member": {"object_type": "USER", "object_guid": "91faf0e8-cfb6-49ea-80a7-e621986443f8"}},
        "dry_run": False,
        "idempotency_key": uuid.uuid4().hex,
        "correlation_id": uuid.uuid4().hex,
        "ticket_id": "TICKET-123",
        "requested_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "nonce": uuid.uuid4().hex,
        "requested_by": "test-caller",
    }
    envelope.update(overrides)
    return envelope


class FakeGateway:
    """In-memory DirectoryGateway stand-in (ping + typed reads + mutations)."""

    def __init__(self) -> None:
        """Seed deterministic directory fixtures."""
        self.members: dict[str, set[str]] = {}
        self.ping_ok = True

    async def ping(self) -> dict[str, Any]:
        """Report reachability (toggle ping_ok to simulate outage)."""
        if not self.ping_ok:
            raise ConnectorError(
                code="LDAP_UNAVAILABLE",
                message="Simulated DC outage.",
                category="DEPENDENCY",
                http_status=503,
                retryable=True,
            )
        return {"ok": True, "detail": "lab-dc"}


class FakeOperationService:
    """Deterministic operation service: verified results + scripted faults.

    Faults are triggered via parameters["simulate"] or sentinel target values,
    keeping every negative test reproducible without a real DC.
    """

    def __init__(self) -> None:
        """Create empty idempotency and membership stores."""
        self._idem: dict[str, tuple[str, dict[str, Any]]] = {}
        self._members: dict[str, set[str]] = {}
        self.executed: list[dict[str, Any]] = []

    @staticmethod
    def _payload_hash(payload: Any) -> str:
        """Hash request payloads for idempotency collision detection."""
        raw = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _verified_result(
        self,
        capability: str,
        target: dict[str, Any],
        disposition: str = "APPLIED",
        state: str = "AD_VERIFIED",
    ) -> dict[str, Any]:
        """Build a verified result (never echoes secrets)."""
        guid = str(target.get("object_guid") or "created-guid")
        return {
            "operation_id": f"op-{uuid.uuid4().hex[:12]}",
            "state": state,
            "disposition": disposition,
            "target_object_guid": guid,
            "changed_fields": ["member"] if capability.startswith("group.member") else ["object"],
            "source_dc": "dc-lab-redacted",
            "verification_evidence": {
                "verification_type": "READ_AFTER_WRITE",
                "object_guid": guid,
                "matched": True,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "redaction_applied": True,
            },
        }

    def _maybe_fault(self, capability: str, target: dict[str, Any], parameters: dict[str, Any]) -> None:
        """Raise scripted domain faults for sentinel inputs (deterministic, no DC needed)."""
        guid = str(target.get("object_guid", ""))
        ident = str(target.get("identifier_value", "") or parameters.get("identifier_value", ""))
        if guid == NOT_FOUND_GUID or ident == "missing":
            raise ConnectorError(
                code="TARGET_NOT_FOUND", message="Target not found.", category="NOT_FOUND", http_status=404
            )
        if ident == "ambiguous":
            raise ConnectorError(
                code="AMBIGUOUS_TARGET",
                message="Identifier resolves to multiple objects.",
                category="AMBIGUOUS",
                http_status=409,
            )
        if ident == "*)(uid=*":
            raise ConnectorError(
                code="REQUEST_INVALID",
                message="Identifier rejected by query profile.",
                category="VALIDATION",
                http_status=400,
            )
        guid_faults: dict[str, tuple[str, str, int]] = {
            PROTECTED_GUID: ("PROTECTED_TARGET", "POLICY", 403),
            OUT_OF_SCOPE_GUID: ("TARGET_OUT_OF_SCOPE", "POLICY", 403),
            APPROVAL_GUID: ("APPROVAL_REQUIRED", "POLICY", 409),
            COLLISION_GUID: ("IDEMPOTENCY_COLLISION", "CONFLICT", 409),
            CONCURRENT_GUID: ("CONCURRENT_MODIFICATION", "CONCURRENCY", 409),
            LDAP_DOWN_GUID: ("LDAP_UNAVAILABLE", "DEPENDENCY", 503),
        }
        if guid in guid_faults:
            code, category, http = guid_faults[guid]
            raise ConnectorError(code=code, message=f"Simulated {code}.", category=category, http_status=http)
        if capability in ("user.attributes.update", "group.attributes.update"):
            allowed = USER_WRITABLE_ATTRIBUTES if capability.startswith("user") else GROUP_WRITABLE_ATTRIBUTES
            attrs = parameters.get("attributes") or {}
            forbidden = sorted(set(attrs) - allowed)
            if forbidden:
                raise ConnectorError(
                    code="CAPABILITY_NOT_ALLOWED",
                    message=f"Attributes outside allowlist: {', '.join(forbidden[:5])}.",
                    category="POLICY",
                    http_status=403,
                )
        simulate = str(parameters.get("simulate", ""))
        faults: dict[str, tuple[str, str, int]] = {
            "protected": ("PROTECTED_TARGET", "POLICY", 403),
            "out_of_scope": ("TARGET_OUT_OF_SCOPE", "POLICY", 403),
            "approval": ("APPROVAL_REQUIRED", "POLICY", 409),
            "collision": ("IDEMPOTENCY_COLLISION", "CONFLICT", 409),
            "concurrent": ("CONCURRENT_MODIFICATION", "CONCURRENCY", 409),
            "ldap_down": ("LDAP_UNAVAILABLE", "DEPENDENCY", 503),
            "forbidden_attr": ("CAPABILITY_NOT_ALLOWED", "POLICY", 403),
        }
        if simulate in faults:
            code, category, http = faults[simulate]
            raise ConnectorError(code=code, message=f"Simulated {code}.", category=category, http_status=http)

    def _read_search(
        self, capability: str, target: dict[str, Any], parameters: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Build canned search/member results; None for non-search capabilities."""
        if capability in ("user.search", "group.search"):
            cursor = parameters.get("cursor") or {}
            if cursor:
                return {"items": [], "next_cursor": None}
            object_type = "USER" if capability.startswith("user") else "GROUP"
            item = {
                "object_type": object_type,
                "object_guid": "91faf0e8-cfb6-49ea-80a7-e621986443f8",
                "distinguished_name": "CN=Test,OU=Users,DC=lab,DC=example,DC=test",
                "domain_id": "domain-lab",
            }
            return {"items": [item], "next_cursor": {"offset": 1}}
        if capability == "group.members.list":
            return {"members": [], "unresolved_count": 0, "next_cursor": None}
        return None

    def _read_result(
        self, capability: str, target: dict[str, Any], parameters: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Build canned read results; None when the capability is a mutation."""
        if capability in ("directory.rootdse.read",):
            return {
                "domain_id": target.get("domain_id", "domain-lab"),
                "forest_id": "forest-lab",
                "naming_contexts": ["DC=lab,DC=example,DC=test"],
            }
        if capability == "directory.capabilities.read":
            return {
                "domain_id": target.get("domain_id", "domain-lab"),
                "capabilities": ["user.resolve", "group.member.add", "account.unlock"],
            }
        if capability in ("user.resolve", "group.resolve"):
            object_type = "USER" if capability.startswith("user") else "GROUP"
            return {
                "object_type": object_type,
                "object_guid": target.get("object_guid") or "91faf0e8-cfb6-49ea-80a7-e621986443f8",
                "distinguished_name": "CN=Test,OU=Users,DC=lab,DC=example,DC=test",
                "domain_id": target.get("domain_id", "domain-lab"),
            }
        if capability in ("user.get", "group.get"):
            object_type = "USER" if capability.startswith("user") else "GROUP"
            return {
                "object_type": object_type,
                "object_guid": target.get("object_guid"),
                "distinguished_name": "CN=Test,OU=Users,DC=lab,DC=example,DC=test",
                "domain_id": "domain-lab",
                "display_name": "Test User",
                "attributes": {},
            }
        return self._read_search(capability, target, parameters)

    def _queued_result(self, capability: str, target: dict[str, Any], state: str) -> dict[str, Any]:
        """Build a queued/authorized result with a status URL."""
        result = self._verified_result(capability, target, state=state)
        result["status_url"] = f"/api/v1/operations/{result['operation_id']}"
        return result

    def _failed_verification_result(self, capability: str, target: dict[str, Any]) -> dict[str, Any]:
        """Build a FAILED_VERIFICATION result with redacted mismatched evidence."""
        result = self._verified_result(capability, target, state="FAILED_VERIFICATION")
        result["verification_evidence"] = {
            "verification_type": "READ_AFTER_WRITE",
            "object_guid": target.get("object_guid"),
            "matched": False,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "redaction_applied": True,
        }
        return result

    def _apply_membership(self, capability: str, target: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
        """Apply add/remove membership with NO_OP idempotency and cycle rejection."""
        member = str(parameters.get("member_guid", ""))
        group = str(target.get("object_guid", ""))
        current = self._members.setdefault(group, set())
        if capability == "group.member.add":
            if member and member == group:
                raise ConnectorError(
                    code="LDAP_CONSTRAINT_VIOLATION",
                    message="Group cycle rejected.",
                    category="CONFLICT",
                    http_status=409,
                )
            if member in current:
                return self._verified_result(capability, target, disposition="NO_OP")
            current.add(member)
            return self._verified_result(capability, target)
        disposition = "NO_OP" if member not in current else "APPLIED"
        current.discard(member)
        return self._verified_result(capability, target, disposition=disposition)

    def _execute_mutation(
        self, capability: str, target: dict[str, Any], parameters: dict[str, Any], dry_run: bool
    ) -> dict[str, Any]:
        """Execute a mutation with scripted async/verify outcomes."""
        if dry_run or parameters.get("dry_run"):
            result = self._verified_result(capability, target, disposition="NO_OP", state="AUTHORIZED")
            result["status_url"] = f"/api/v1/operations/{result['operation_id']}"
            return result
        if parameters.get("simulate") == "queued" or str(target.get("object_guid")) == QUEUED_GUID:
            return self._queued_result(capability, target, "RECEIVED")
        if parameters.get("simulate") == "failed_verification" or str(target.get("object_guid")) == FAILED_VERIFY_GUID:
            return self._failed_verification_result(capability, target)
        if capability in ("group.member.add", "group.member.remove"):
            return self._apply_membership(capability, target, parameters)
        if capability == "account.unlock" and str(target.get("object_guid", "")).endswith("noop"):
            return self._verified_result(capability, target, disposition="NO_OP")
        return self._verified_result(capability, target)

    def _reserve_idempotency(self, idempotency_key: str | None, payload_hash: str) -> dict[str, Any] | None:
        """Return the stored result on safe replay; raise on payload collision."""
        if not idempotency_key:
            return None
        seen = self._idem.get(idempotency_key)
        if seen is None:
            return None
        if seen[0] != payload_hash:
            raise ConnectorError(
                code="IDEMPOTENCY_COLLISION",
                message="Idempotency key reused with a different payload.",
                category="CONFLICT",
                http_status=409,
            )
        return dict(seen[1])

    async def execute_capability(  # noqa: PLR0913 - fake mirrors the service seam explicitly.
        self,
        *,
        capability: str,
        target: dict[str, Any],
        parameters: dict[str, Any],
        caller: Any,
        idempotency_key: str | None,
        correlation_id: str,
        ticket_id: str | None,
        dry_run: bool,
    ) -> dict[str, Any]:
        """Execute with idempotency reservation, scripted faults, and verified results."""
        _ = (caller, correlation_id, ticket_id)
        self._maybe_fault(capability, target, parameters)
        read = self._read_result(capability, target, parameters)
        if read is not None:
            return read

        # Mutations: idempotency reservation with collision detection.
        payload_hash = self._payload_hash({"capability": capability, "target": target, "parameters": parameters})
        replayed = self._reserve_idempotency(idempotency_key, payload_hash)
        if replayed is not None:
            return replayed
        result = self._execute_mutation(capability, target, parameters, dry_run)
        self.executed.append({"capability": capability, "target": target})
        if idempotency_key:
            self._idem[idempotency_key] = (payload_hash, dict(result))
        return result

    async def get_operation(self, operation_id: str, caller: Any) -> dict[str, Any] | None:
        """Return a canned record, None for the op-missing sentinel."""
        _ = caller
        if operation_id == "op-missing":
            return None
        now = datetime.now(timezone.utc).isoformat()
        return {
            "operation_id": operation_id,
            "state": "AD_VERIFIED",
            "capability": "group.member.add",
            "disposition": "APPLIED",
            "target_object_guid": "7e565f72-8274-4cb8-b77a-7dad17a1b432",
            "verification_evidence": {"matched": True, "redaction_applied": True},
            "created_at": now,
            "updated_at": now,
        }

    async def search_operations(
        self, filters: dict[str, str], page_size: int, page_token: Any, caller: Any
    ) -> dict[str, Any]:
        """Return one canned item (no continuation)."""
        _ = (filters, page_size, page_token, caller)
        return {
            "items": [{"operation_id": "op-1", "state": "AD_VERIFIED", "capability": "group.member.add"}],
            "next_cursor": None,
        }

    async def get_audit(self, audit_id: str, caller: Any) -> dict[str, Any] | None:
        """Return a canned audit record, None for the audit-missing sentinel."""
        _ = caller
        if audit_id == "audit-missing":
            return None
        return {
            "audit_id": audit_id,
            "operation_id": "op-1",
            "entries": [{"event": "authorized", "at": "2026-01-15T10:00:00Z"}],
            "chain_reference": "chain-1",
        }

    async def export_audit(self, params: dict[str, Any], caller: Any) -> dict[str, Any]:
        """Return an export receipt."""
        _ = (params, caller)
        return {"export_id": "exp-1", "state": "RECEIVED", "status_url": "/api/v1/operations/exp-1"}

    async def get_health(self) -> dict[str, Any]:
        """Return healthy liveness info."""
        return {"status": "HEALTHY"}

    async def get_readiness(self) -> dict[str, Any]:
        """Return all-healthy readiness checks."""
        return {
            "ready": True,
            "checks": [
                {"name": "operation_store", "healthy": True, "detail": "ok"},
                {"name": "audit_store", "healthy": True, "detail": "ok"},
                {"name": "transport", "healthy": True, "detail": "ok"},
            ],
        }


@pytest.fixture
def settings() -> RuntimeConfig:
    """Test runtime config (test-only secrets)."""
    return make_settings()


@pytest.fixture
def fake_service() -> FakeOperationService:
    """Fresh fake operation service per test."""
    return FakeOperationService()


@pytest.fixture
def fake_gateway() -> FakeGateway:
    """Fresh fake gateway per test."""
    return FakeGateway()


@pytest.fixture
def tenant_id() -> str:
    """Bound tenant id for worker/binding tests."""
    return TEST_TENANT_ID


@pytest.fixture
def connector_id() -> str:
    """Bound connector id for worker/binding tests."""
    return TEST_CONNECTOR_ID


@pytest.fixture
def envelope_factory() -> Any:
    """Factory building valid command envelopes (override kwargs per test)."""
    return make_envelope


@pytest.fixture
def app(settings: RuntimeConfig, fake_service: FakeOperationService, fake_gateway: FakeGateway) -> Any:
    """FastAPI app wired to fakes via dependency overrides."""
    application = create_app(settings)
    application.dependency_overrides[deps.get_settings] = lambda: settings
    application.dependency_overrides[deps.get_operation_service] = lambda: fake_service
    application.dependency_overrides[deps.get_gateway] = lambda: fake_gateway
    return application


@pytest.fixture
def client(app: Any) -> TestClient:
    """Synchronous test client for the wired app."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def headers(settings: RuntimeConfig) -> dict[str, str]:
    """Full authenticated header set with all scopes."""
    return auth_headers(settings)


def utcnow_iso() -> str:
    """Current UTC time as ISO string (header/envelope helper)."""
    return datetime.now(timezone.utc).isoformat()


def expired_iso() -> str:
    """Timestamp 10 minutes in the past (expiry-path helper)."""
    return (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()


def _unused() -> float:
    """Keep time import used for potential timing assertions."""
    return time.monotonic()
