"""Caller authentication: CallerContext built from a validated JWT payload (Step 8).

The payload must already be validated by :mod:`mwa_ad_connector.security.jwt_validation`;
this module maps it onto the typed :class:`CallerContext` (plan section 6.6)
without taking any LDAP or authorization decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.security.jwt_validation import AuthenticationFailed


class AuthMethod(StrEnum):
    """How the caller authenticated to the connector."""

    JWT = "JWT"
    MTLS = "MTLS"
    JWT_MTLS = "JWT_MTLS"


class CallerContext(BaseModel):
    """Identity of an already-authenticated caller (plan section 6.6)."""

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1)
    issuer: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    customer_id: str = Field(min_length=1)
    connector_id: str = Field(min_length=1)
    scopes: list[str] = Field(min_length=1)
    roles: list[str] = Field(default_factory=list)
    certificate_thumbprint: str | None = None
    auth_method: AuthMethod
    token_id: str | None = None
    authenticated_at: datetime


def _as_str_list(value: Any, *, claim: str) -> list[str]:
    if isinstance(value, str):
        items = value.split()
    elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        items = list(value)
    else:
        raise AuthenticationFailed(f"claim {claim!r} must be a string or a string list")
    cleaned = [item.strip() for item in items if item.strip()]
    if not cleaned:
        raise AuthenticationFailed(f"claim {claim!r} must not be empty")
    return cleaned


def _required_str(payload: Mapping[str, Any], claim: str) -> str:
    value = payload.get(claim)
    if not isinstance(value, str) or not value.strip():
        raise AuthenticationFailed(f"claim {claim!r} must be a non-empty string")
    return value.strip()


def build_caller_context(
    payload: Mapping[str, Any],
    *,
    auth_method: AuthMethod,
    certificate_thumbprint: str | None = None,
    authenticated_at: datetime | None = None,
) -> CallerContext:
    """Build a :class:`CallerContext` from an already-validated JWT payload.

    Raises:
        AuthenticationFailed: On missing/invalid claims, on an ambiguous
            list ``aud``, or when mTLS methods lack a certificate thumbprint.
    """
    audience_raw = payload.get("aud")
    if isinstance(audience_raw, str):
        audience = audience_raw.strip()
    elif isinstance(audience_raw, (list, tuple)) and len(audience_raw) == 1:
        first: Any = audience_raw[0]
        audience = first.strip() if isinstance(first, str) else ""
    else:
        audience = ""
    if not audience:
        raise AuthenticationFailed("claim 'aud' must be a single audience value")
    token_raw = payload.get("jti")
    token_id = token_raw.strip() if isinstance(token_raw, str) and token_raw.strip() else None
    if auth_method in (AuthMethod.MTLS, AuthMethod.JWT_MTLS) and not certificate_thumbprint:
        raise AuthenticationFailed(f"auth method {auth_method.value} requires a client certificate")
    return CallerContext(
        subject=_required_str(payload, "sub"),
        issuer=_required_str(payload, "iss"),
        audience=audience,
        tenant_id=_required_str(payload, "tenant_id"),
        customer_id=_required_str(payload, "customer_id"),
        connector_id=_required_str(payload, "connector_id"),
        scopes=_as_str_list(payload.get("scopes"), claim="scopes"),
        roles=_as_str_list(payload.get("roles", []), claim="roles") if payload.get("roles") is not None else [],
        certificate_thumbprint=certificate_thumbprint,
        auth_method=auth_method,
        token_id=token_id,
        authenticated_at=authenticated_at or datetime.now(UTC),
    )
