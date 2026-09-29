"""Shared schemas: errors, operation status, approvals, health, HMAC page tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

_HEALTH_VERSION = "1.0"


class ApprovalContext(BaseModel):
    """Approval evidence attached to policy-gated mutations."""

    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1, max_length=128)
    approved_by: list[str] = Field(min_length=1, max_length=8)
    approved_at: datetime


class ErrorDetail(BaseModel):
    """Stable, redacted error body (raw LDAP text must never appear here)."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=64)
    category: str = Field(min_length=1, max_length=32)
    message: str = Field(min_length=1, max_length=1000)
    retryable: bool = False
    operation_id: str | None = Field(default=None, max_length=128)
    correlation_id: str | None = Field(default=None, max_length=128)
    details: dict[str, str] = Field(default_factory=dict)
    remediation: str | None = Field(default=None, max_length=1000)
    dependency_code: str | None = Field(default=None, max_length=64)


class ErrorResponse(BaseModel):
    """Top-level error envelope returned for every 4xx/5xx."""

    model_config = ConfigDict(extra="forbid")

    error: ErrorDetail
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OperationStatusResponse(BaseModel):
    """Synchronous verified result (200) or queued work receipt (202)."""

    model_config = ConfigDict(extra="forbid")

    operation_id: str = Field(min_length=1, max_length=128)
    state: str = Field(min_length=1, max_length=32)
    disposition: str | None = Field(default=None, max_length=32)
    status_url: str | None = Field(default=None, max_length=512)
    target_object_guid: str | None = Field(default=None, max_length=64)
    changed_fields: list[str] = Field(default_factory=list)
    source_dc: str | None = Field(default=None, max_length=128)
    verification_evidence: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    """Anonymous, redacted liveness probe (no DNs, hostnames, or thumbprints)."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(pattern="^(HEALTHY|DEGRADED|UNHEALTHY)$")
    version: str = Field(min_length=1, max_length=32)
    connector_id: str = Field(min_length=1, max_length=128)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ComponentStatus(BaseModel):
    """Single readiness check outcome (redacted detail only)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    healthy: bool
    detail: str = Field(default="", max_length=256)


class ReadinessResponse(BaseModel):
    """Readiness probe: 200 when safe to operate, 503 otherwise."""

    model_config = ConfigDict(extra="forbid")

    ready: bool
    version: str = Field(min_length=1, max_length=32)
    checks: list[ComponentStatus] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PageTokenRequest(BaseModel):
    """Pagination input shared by search endpoints."""

    model_config = ConfigDict(extra="forbid")

    page_size: int = Field(default=50, ge=1, le=1000)
    page_token: str | None = Field(default=None, max_length=4096)


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Decode unpadded base64url, raising ValueError on malformed input."""
    try:
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise ValueError("PAGE_TOKEN_MALFORMED") from exc


def create_page_token(payload: dict[str, Any], secret: str, ttl_seconds: int = 300) -> str:
    """Create an HMAC-signed opaque page token.

    Args:
        payload: Cursor payload (offset, query hash, scope fingerprint).
        secret: HMAC key (connector secret, never exposed).
        ttl_seconds: Token lifetime; expired tokens are rejected.

    Returns:
        Opaque token string safe for URLs.
    """
    body = {"v": _HEALTH_VERSION, "exp": int(time.time()) + ttl_seconds, "payload": payload}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{_b64url_encode(raw)}.{_b64url_encode(sig)}"


def verify_page_token(token: str, secret: str) -> dict[str, Any]:
    """Verify a page token signature/expiry and return its cursor payload.

    Args:
        token: Opaque token previously issued by create_page_token.
        secret: HMAC key used at issuance.

    Returns:
        The cursor payload dict.

    Raises:
        ValueError: With code PAGE_TOKEN_MALFORMED, PAGE_TOKEN_INVALID or PAGE_TOKEN_EXPIRED.
    """
    try:
        raw_b64, sig_b64 = token.split(".", 1)
    except ValueError as exc:
        raise ValueError("PAGE_TOKEN_MALFORMED") from exc
    raw = _b64url_decode(raw_b64)
    sig = _b64url_decode(sig_b64)
    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("PAGE_TOKEN_INVALID")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("PAGE_TOKEN_MALFORMED") from exc
    if not isinstance(body, dict) or body.get("v") != _HEALTH_VERSION:
        raise ValueError("PAGE_TOKEN_INVALID")
    if int(body.get("exp", 0)) < int(time.time()):
        raise ValueError("PAGE_TOKEN_EXPIRED")
    payload = body.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("PAGE_TOKEN_MALFORMED")
    return payload
