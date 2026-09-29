"""Coverage boost: security track (jwt, authentication, authorization, anti-replay, mtls, secrets, redaction)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest

from mwa_ad_connector.security.anti_replay import AntiReplayService, ReplayDetected, StaleTimestamp
from mwa_ad_connector.security.authentication import AuthMethod, build_caller_context
from mwa_ad_connector.security.authorization import (
    CallerForbidden,
    check_connector_binding,
    check_tenant_binding,
    require_any_scope,
    require_scope,
)
from mwa_ad_connector.security.jwt_validation import AuthenticationFailed, validate_jwt
from mwa_ad_connector.security.mtls import extract_thumbprint, verify_mtls_binding
from mwa_ad_connector.security.redaction import (
    attribute_hashes,
    hash_value,
    is_sensitive_key,
    redact_dict,
    redact_dn_for_logs,
)
from mwa_ad_connector.security.secrets import (
    SecretError,
    clear_buffer,
    load_secret_from_env_or_file,
    read_secret_file,
    reveal,
)

_TEST_SECRET = "boost-test-secret-32-bytes-minimum!!"  # noqa: S105 - test-only HMAC key.
_ISSUER = "https://issuer.lab"
_AUDIENCE = "connector-lab"


def _mint(payload_overrides: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": "caller-1",
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "exp": now + timedelta(minutes=5),
        "iat": now,
        "tenant_id": "t1",
        "customer_id": "c-cust",
        "connector_id": "c-conn",
        "scopes": ["ad.user.read"],
    }
    if payload_overrides:
        payload.update(payload_overrides)
    return jwt.encode(payload, _TEST_SECRET, algorithm="HS256")


def test_jwt_empty_token_rejected() -> None:
    with pytest.raises(AuthenticationFailed):
        validate_jwt("", key=_TEST_SECRET, algorithms=["HS256"], issuers=[_ISSUER])


def test_jwt_none_algorithm_never_accepted() -> None:
    token = _mint()
    with pytest.raises(AuthenticationFailed, match="none"):
        validate_jwt(token, key=_TEST_SECRET, algorithms=["none"], issuers=[_ISSUER])


def test_jwt_no_trust_config_rejected() -> None:
    token = _mint()
    with pytest.raises(AuthenticationFailed, match="no trusted"):
        validate_jwt(token, key=_TEST_SECRET, algorithms=["HS256"], issuers=[], audiences=[])


def test_jwt_bad_signature_rejected() -> None:
    token = _mint()
    with pytest.raises(AuthenticationFailed):
        validate_jwt(token, key="wrong-secret-value-000000000000", algorithms=["HS256"], issuers=[_ISSUER])


def test_jwt_wrong_issuer_rejected() -> None:
    token = _mint({"iss": "https://evil.example"})
    with pytest.raises(AuthenticationFailed):
        validate_jwt(token, key=_TEST_SECRET, algorithms=["HS256"], issuers=[_ISSUER])


def test_jwt_missing_claims_rejected() -> None:
    now = datetime.now(timezone.utc)
    payload = {"sub": "x", "iss": _ISSUER, "exp": now + timedelta(minutes=5)}
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    with pytest.raises(AuthenticationFailed, match="required claim"):
        validate_jwt(token, key=_TEST_SECRET, algorithms=["HS256"], issuers=[_ISSUER])


def test_jwt_valid_returns_payload() -> None:
    token = _mint()
    payload = validate_jwt(token, key=_TEST_SECRET, algorithms=["HS256"], issuers=[_ISSUER])
    assert payload["sub"] == "caller-1"
    assert payload["tenant_id"] == "t1"


def _caller_payload() -> dict[str, Any]:
    return {
        "sub": "caller-1",
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "tenant_id": "t1",
        "customer_id": "cust-1",
        "connector_id": "conn-1",
        "scopes": "ad.user.read ad.group.read",
        "roles": ["operator"],
        "jti": "tok-1",
    }


def test_build_caller_context_ok() -> None:
    ctx = build_caller_context(_caller_payload(), auth_method=AuthMethod.JWT)
    assert ctx.subject == "caller-1"
    assert ctx.audience == _AUDIENCE
    assert ctx.scopes == ["ad.user.read", "ad.group.read"]
    assert ctx.token_id == "tok-1"  # noqa: S105 - test-only opaque token id.


def test_build_caller_context_single_item_aud_list() -> None:
    payload = _caller_payload()
    payload["aud"] = [_AUDIENCE]
    ctx = build_caller_context(payload, auth_method=AuthMethod.JWT)
    assert ctx.audience == _AUDIENCE


def test_build_caller_context_rejects_multi_aud() -> None:
    payload = _caller_payload()
    payload["aud"] = ["a", "b"]
    with pytest.raises(AuthenticationFailed):
        build_caller_context(payload, auth_method=AuthMethod.JWT)


def test_build_caller_context_mtls_requires_thumbprint() -> None:
    with pytest.raises(AuthenticationFailed):
        build_caller_context(_caller_payload(), auth_method=AuthMethod.MTLS)
    ctx = build_caller_context(_caller_payload(), auth_method=AuthMethod.MTLS, certificate_thumbprint="abc123")
    assert ctx.certificate_thumbprint == "abc123"


def test_build_caller_context_bad_scopes() -> None:
    payload = _caller_payload()
    payload["scopes"] = [123]
    with pytest.raises(AuthenticationFailed):
        build_caller_context(payload, auth_method=AuthMethod.JWT)
    payload["scopes"] = "   "
    with pytest.raises(AuthenticationFailed):
        build_caller_context(payload, auth_method=AuthMethod.JWT)


def test_build_caller_context_missing_str_claim() -> None:
    payload = _caller_payload()
    del payload["sub"]
    with pytest.raises(AuthenticationFailed):
        build_caller_context(payload, auth_method=AuthMethod.JWT)


def test_require_scope_ok_and_missing() -> None:
    ctx = build_caller_context(_caller_payload(), auth_method=AuthMethod.JWT)
    require_scope(ctx, "ad.user.read")
    with pytest.raises(CallerForbidden):
        require_scope(ctx, "ad.admin")


def test_require_any_scope() -> None:
    ctx = build_caller_context(_caller_payload(), auth_method=AuthMethod.JWT)
    require_any_scope(ctx, ["ad.admin", "ad.group.read"])
    with pytest.raises(CallerForbidden):
        require_any_scope(ctx, ["ad.admin"])


def test_tenant_connector_binding() -> None:
    ctx = build_caller_context(_caller_payload(), auth_method=AuthMethod.JWT)
    check_tenant_binding(ctx, "t1")
    check_connector_binding(ctx, "conn-1")
    with pytest.raises(CallerForbidden):
        check_tenant_binding(ctx, "other")
    with pytest.raises(CallerForbidden):
        check_connector_binding(ctx, "other")
    with pytest.raises(CallerForbidden):
        check_tenant_binding(ctx, "")
    with pytest.raises(CallerForbidden):
        check_connector_binding(ctx, "")


class _MemNonceStore:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def claim(self, nonce: str, expires_at: float) -> bool:
        _ = expires_at
        if nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True

    def purge_expired(self, now: float) -> int:
        _ = now
        return 0


def test_anti_replay_ok_and_replay_detected() -> None:
    svc = AntiReplayService(_MemNonceStore())
    now = 1_700_000_000.0
    svc.check(timestamp=now, nonce="n-1", now=now)
    with pytest.raises(ReplayDetected):
        svc.check(timestamp=now, nonce="n-1", now=now)


def test_anti_replay_bad_nonce_and_stale() -> None:
    svc = AntiReplayService(_MemNonceStore())
    now = 1_700_000_000.0
    with pytest.raises(AuthenticationFailed):
        svc.check(timestamp=now, nonce="  ", now=now)
    with pytest.raises(AuthenticationFailed):
        svc.check(timestamp=now, nonce="x" * 300, now=now)
    with pytest.raises(StaleTimestamp):
        svc.check(timestamp=now - 10_000, nonce="fresh", now=now)


def test_anti_replay_bad_windows() -> None:
    with pytest.raises(ValueError):
        AntiReplayService(_MemNonceStore(), max_skew_seconds=0)
    svc = AntiReplayService(_MemNonceStore(), max_skew_seconds=300, nonce_ttl_seconds=600)
    assert svc.max_skew_seconds == 300.0
    assert svc.nonce_ttl_seconds == 600.0


def test_mtls_thumbprint_and_binding() -> None:
    thumb = extract_thumbprint(b"fake-der-bytes")
    assert len(thumb) == 64
    with pytest.raises(ValueError):
        extract_thumbprint(b"")
    with pytest.raises(ValueError, match="unsupported"):
        extract_thumbprint(b"der", algorithm="nope-md")
    assert verify_mtls_binding(presented_thumbprint=None, expected_thumbprint=None) is True
    assert verify_mtls_binding(presented_thumbprint=None, expected_thumbprint=None, enforce=True) is False
    assert verify_mtls_binding(presented_thumbprint=None, expected_thumbprint="aa") is False
    assert verify_mtls_binding(presented_thumbprint="AA", expected_thumbprint="aa") is True
    assert verify_mtls_binding(presented_thumbprint="bb", expected_thumbprint="aa") is False


def test_secrets_file_and_env(tmp_path: Any, monkeypatch: Any) -> None:
    target = tmp_path / "secret.txt"
    target.write_text("s3cret-value\n", encoding="utf-8")
    secret = read_secret_file(target)
    assert reveal(secret) == "s3cret-value"
    with pytest.raises(SecretError):
        read_secret_file(tmp_path / "missing.txt")
    monkeypatch.setenv("BOOST_SECRET", "env-value")
    monkeypatch.delenv("BOOST_SECRET_FILE", raising=False)
    loaded = load_secret_from_env_or_file("BOOST_SECRET")
    assert reveal(loaded) == "env-value"
    monkeypatch.setenv("BOOST_SECRET_FILE", str(target))
    loaded2 = load_secret_from_env_or_file("BOOST_SECRET")
    assert reveal(loaded2) == "s3cret-value"
    monkeypatch.delenv("BOOST_SECRET", raising=False)
    monkeypatch.delenv("BOOST_SECRET_FILE", raising=False)
    assert load_secret_from_env_or_file("BOOST_SECRET") is None
    assert reveal(None) is None
    buf = bytearray(b"secret-bytes")
    clear_buffer(buf)
    assert bytes(buf) == b"\x00" * len(buf)


def test_redaction_helpers() -> None:
    assert is_sensitive_key("new_password") is True
    assert is_sensitive_key(" samAccountName ") is False
    assert is_sensitive_key("myTokenValue") is True
    redacted = redact_dict({"password": "x", "nested": {"token": "y", "name": "n"}, "plain": "v"})
    assert redacted["password"] == "***REDACTED***"  # noqa: S105 - redaction placeholder assertion.
    assert redacted["nested"] == {"token": "***REDACTED***", "name": "n"}
    assert redact_dn_for_logs("CN=Jane Doe,OU=Users,DC=lab,DC=local") == "CN=***,OU=***,DC=lab,DC=local"
    assert redact_dn_for_logs("") == "REDACTED-DN"
    assert redact_dn_for_logs("not-a-dn") == "REDACTED-DN"
    assert len(hash_value("abc")) == 64
    digests = attribute_hashes({"mail": "a@b.c", "multi": ["x", "y"]})
    assert set(digests) == {"mail", "multi"}
    assert len(digests["multi"]) == 2


def test_redact_dict_strips_env_secret(monkeypatch: Any) -> None:
    monkeypatch.setenv("BOOST_OTHER", "v")
    out = redact_dict({"BOOST_OTHER": "v", "displayName": "Jane"})
    assert out["displayName"] == "Jane"
    assert out["BOOST_OTHER"] == "v"
    os.environ.pop("BOOST_OTHER", None)
