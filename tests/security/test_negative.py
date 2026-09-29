"""Security negatives: auth, binding, scope, policy, injection, limits, leakage."""

import json
import logging
import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient

from mwa_ad_connector.api import dependencies as deps
from mwa_ad_connector.api.app import create_app
from mwa_ad_connector.api.middleware.rate_limit import RateLimiter, RateLimitMiddleware
from tests.conftest import (
    APPROVAL_GUID,
    COLLISION_GUID,
    FAILED_VERIFY_GUID,
    OUT_OF_SCOPE_GUID,
    PROTECTED_GUID,
    QUEUED_GUID,
    auth_headers,
)

pytestmark = pytest.mark.security

USER_GUID = "91faf0e8-cfb6-49ea-80a7-e621986443f8"
GROUP_GUID = "7e565f72-8274-4cb8-b77a-7dad17a1b432"


def _unlock(
    client: TestClient, headers: dict[str, str], guid: str = USER_GUID, body: dict[str, Any] | None = None
) -> Any:
    """POST an unlock mutation, rotating the idempotency key only when present."""
    fresh = dict(headers)
    if "Idempotency-Key" in fresh:
        fresh["Idempotency-Key"] = uuid.uuid4().hex
    return client.post(f"/api/v1/users/{guid}:unlock", json=body or {"reason": "test"}, headers=fresh)


def test_anonymous_mutation_rejected_401(client: TestClient) -> None:
    """No bearer token: mutations fail closed with 401 (no anonymous fallback)."""
    response = client.post(
        f"/api/v1/users/{USER_GUID}:unlock", json={}, headers={"X-Tenant-ID": "t", "X-Connector-ID": "c"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_expired_token_rejected_401(client: TestClient, settings: Any) -> None:
    """Expired JWT is rejected even with otherwise valid headers."""
    headers = auth_headers(settings, expired=True)
    assert _unlock(client, headers).status_code == 401


def test_wrong_audience_rejected_401(client: TestClient, settings: Any) -> None:
    """JWT for another audience is rejected (allowlisted iss/aud enforced)."""
    headers = auth_headers(settings, wrong_audience=True)
    assert _unlock(client, headers).status_code == 401


def test_tenant_mismatch_rejected_403(client: TestClient, settings: Any) -> None:
    """X-Tenant-ID diverging from the token tenant is a binding violation."""
    headers = auth_headers(settings, tenant_id="tenant-evil")
    headers["X-Tenant-ID"] = "tenant-lab"  # header says lab, token says evil.
    response = _unlock(client, headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "TENANT_BINDING_MISMATCH"


def test_connector_mismatch_rejected_403(client: TestClient, headers: dict[str, str]) -> None:
    """X-Connector-ID diverging from local binding is rejected."""
    headers = dict(headers, **{"X-Connector-ID": "connector-evil"})
    response = _unlock(client, headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "TENANT_BINDING_MISMATCH"


def test_missing_scope_rejected_403(client: TestClient, settings: Any) -> None:
    """Authenticated caller without the capability scope gets 403 (not 500)."""
    headers = auth_headers(settings, scopes=["ad.user.read"])
    response = _unlock(client, headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CALLER_FORBIDDEN"


def test_missing_idempotency_key_rejected_400(client: TestClient, settings: Any) -> None:
    """Mutations require Idempotency-Key (fail-closed, explicit remediation)."""
    headers = auth_headers(settings, include_idempotency=False)
    response = _unlock(client, headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REQUEST_INVALID"


def test_missing_ticket_rejected_400(client: TestClient, settings: Any) -> None:
    """Mutations require X-Ticket-ID (MWA correlation contract)."""
    headers = auth_headers(settings, include_ticket=False)
    response = _unlock(client, headers)
    assert response.status_code == 400


def test_out_of_scope_target_403(client: TestClient, headers: dict[str, str]) -> None:
    """Targets outside managed scope are denied by policy (403, no LDAP touch)."""
    response = client.post(
        f"/api/v1/groups/{OUT_OF_SCOPE_GUID}/members:add", json={"member_guid": USER_GUID}, headers=headers
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "TARGET_OUT_OF_SCOPE"


def test_protected_target_403(client: TestClient, headers: dict[str, str]) -> None:
    """Privileged/protected targets are denied (403 PROTECTED_TARGET)."""
    response = _unlock(client, headers, guid=PROTECTED_GUID)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PROTECTED_TARGET"


def test_approval_gated_409(client: TestClient, headers: dict[str, str]) -> None:
    """Policy-gated capability without approval context returns 409."""
    response = _unlock(client, headers, guid=APPROVAL_GUID)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "APPROVAL_REQUIRED"


def test_idempotency_collision_409(client: TestClient, headers: dict[str, str]) -> None:
    """Same key + different payload is a 409 collision (never silent overwrite)."""
    response = _unlock(client, headers, guid=COLLISION_GUID)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "IDEMPOTENCY_COLLISION"


def test_injection_identifier_rejected_400(client: TestClient, headers: dict[str, str]) -> None:
    """LDAP metacharacters in identifiers are rejected by query profiles (no raw filter)."""
    response = client.post(
        "/api/v1/users:resolve",
        json={
            "object_type": "USER",
            "domain_id": "domain-lab",
            "identifier_type": "SAM_ACCOUNT_NAME",
            "identifier_value": "*)(uid=*",
        },
        headers=headers,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REQUEST_INVALID"


def test_forbidden_attribute_403(client: TestClient, headers: dict[str, str]) -> None:
    """Non-allowlisted attributes are policy-denied (no generic PATCH exists)."""
    response = client.post(
        f"/api/v1/users/{USER_GUID}:update-attributes", json={"attributes": {"unicodePwd": "x"}}, headers=headers
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CAPABILITY_NOT_ALLOWED"


def test_oversized_payload_413(client: TestClient, headers: dict[str, str]) -> None:
    """Bodies over the payload limit are rejected with 413 before routing."""
    big = "A" * (1_048_576 + 16)
    response = client.post(
        "/api/v1/users:resolve",
        json={"object_type": "USER", "domain_id": "domain-lab", "identifier_value": big},
        headers=headers,
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_failed_verification_502_with_evidence(client: TestClient, headers: dict[str, str]) -> None:
    """Commit-ok/verify-fail is 502 FAILED_VERIFICATION with redacted evidence."""
    response = _unlock(client, headers, guid=FAILED_VERIFY_GUID)
    assert response.status_code == 502
    body = response.json()
    assert body["state"] == "FAILED_VERIFICATION"
    assert body["verification_evidence"]["redaction_applied"] is True


def test_queued_mutation_returns_202_with_status_url(client: TestClient, headers: dict[str, str]) -> None:
    """Really-queued work returns 202 with operation_id + status_url (§3.5)."""
    response = _unlock(client, headers, guid=QUEUED_GUID)
    assert response.status_code == 202
    body = response.json()
    assert body["state"] == "RECEIVED"
    assert body["status_url"] == f"/api/v1/operations/{body['operation_id']}"


def test_password_leakage_scan(client: TestClient, headers: dict[str, str], caplog: Any) -> None:
    """Reset-password responses (and captured logs) never contain the cleartext secret."""
    secret = "Sup3r-Secret-For-Leak-Scan-Only"  # noqa: S105 - synthetic canary, never a real credential.
    with caplog.at_level(logging.INFO, logger="worker"):
        response = client.post(
            f"/api/v1/users/{USER_GUID}:reset-password",
            json={"new_password": secret, "force_change_at_logon": True},
            headers=headers,
        )
    assert response.status_code == 200
    assert secret not in response.text
    assert secret not in caplog.text
    assert "new_password" not in response.json()


def test_tampered_page_token_400(client: TestClient, headers: dict[str, str]) -> None:
    """Altered page tokens are rejected (HMAC integrity, no cursor forgery)."""
    response = client.post(
        "/api/v1/users:search",
        json={
            "domain_id": "domain-lab",
            "object_type": "USER",
            "query_profile": "by-name",
            "page_token": "forged.token",
        },
        headers=headers,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REQUEST_INVALID"


def test_unknown_operation_filter_400(client: TestClient, headers: dict[str, str]) -> None:
    """Free-form operation search is rejected (allowlisted filters only)."""
    response = client.post("/api/v1/operations:search", json={"filters": {"ldap_filter": "(uid=*)"}}, headers=headers)
    assert response.status_code == 400


def test_unknown_operation_404(client: TestClient, headers: dict[str, str]) -> None:
    """Unknown operation ids are 404 (no cross-tenant oracle)."""
    response = client.get("/api/v1/operations/op-missing", headers=headers)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TARGET_NOT_FOUND"


def test_health_anonymous_and_redacted(client: TestClient) -> None:
    """Health is anonymous and exposes no topology secrets."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "HEALTHY"
    assert "distinguished_name" not in json.dumps(body).lower()
    assert response.headers.get("X-Correlation-ID"), "Correlation id must be echoed."


def test_readiness_requires_scope(client: TestClient, settings: Any) -> None:
    """Readiness without the scope is 401/403; with scope it reports checks."""
    anon = client.get("/api/v1/readiness")
    assert anon.status_code in (401, 403)
    scoped = client.get(
        "/api/v1/readiness",
        headers=auth_headers(settings, scopes=["ad.readiness.read"], include_idempotency=False, include_ticket=False),
    )
    assert scoped.status_code == 200
    assert scoped.json()["ready"] is True


def test_readiness_503_when_gateway_down(client: TestClient, settings: Any, fake_gateway: Any) -> None:
    """Readiness fails (503) when LDAP is unreachable (fail-closed operations)."""
    fake_gateway.ping_ok = False
    try:
        headers = auth_headers(settings, scopes=["ad.readiness.read"], include_idempotency=False, include_ticket=False)
        response = client.get("/api/v1/readiness", headers=headers)
        assert response.status_code == 503
        assert response.json()["ready"] is False
    finally:
        fake_gateway.ping_ok = True


def test_rate_limiter_burst_then_429() -> None:
    """Token bucket allows bursts then answers 429 with Retry-After."""
    inner = FastAPI()
    inner.add_middleware(RateLimitMiddleware, limiter=RateLimiter(capacity=2, refill_per_second=0.1))

    @inner.get("/ping")
    async def ping() -> PlainTextResponse:
        return PlainTextResponse("pong")

    limited = TestClient(inner, raise_server_exceptions=False)
    assert limited.get("/ping").status_code == 200
    assert limited.get("/ping").status_code == 200
    rejected = limited.get("/ping")
    assert rejected.status_code == 429
    assert rejected.headers.get("Retry-After")
    assert rejected.json()["error"]["code"] == "RATE_LIMITED"


def test_stale_timestamp_rejected_401(client: TestClient, headers: dict[str, str]) -> None:
    """X-Request-Timestamp outside the skew window is rejected (replay guard)."""
    stale = dict(headers, **{"X-Request-Timestamp": "2020-01-01T00:00:00Z"})
    assert _unlock(client, stale).status_code == 401
    malformed = dict(headers, **{"X-Request-Timestamp": "not-a-time"})
    assert _unlock(client, malformed).status_code == 401


def test_oversized_idempotency_key_400(client: TestClient, headers: dict[str, str]) -> None:
    """Idempotency keys beyond 128 chars are rejected before any execution."""
    big = dict(headers, **{"Idempotency-Key": "k" * 200})
    response = client.post(f"/api/v1/users/{USER_GUID}:unlock", json={"reason": "t"}, headers=big)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REQUEST_INVALID"


def test_unwired_ports_fail_closed_503(settings: Any) -> None:
    """Without a wired operation service, mutations fail closed with 503 (never fake success)."""
    bare = create_app(settings)
    bare.dependency_overrides[deps.get_settings] = lambda: settings
    probe = TestClient(bare, raise_server_exceptions=False)
    response = probe.post(f"/api/v1/users/{USER_GUID}:unlock", json={"reason": "t"}, headers=auth_headers(settings))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "LDAP_UNAVAILABLE"


def test_no_forbidden_endpoints_registered(client: TestClient) -> None:
    """Banned generic endpoints (/ldap, /query, /powershell, /commands, /shell) are absent."""
    routes = getattr(client.app, "routes", [])
    paths = [getattr(route, "path", "") for route in routes]
    forbidden = ("/ldap", "/query", "/powershell", "/commands", "/shell", "/objects/")
    for path in paths:
        assert not any(token in path for token in forbidden), f"Forbidden route present: {path}"
