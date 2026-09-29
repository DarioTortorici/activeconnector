"""JWT validation with PyJWT: allowlisted issuer/audience, skew, required claims (Step 8)."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Any

import jwt


class AuthenticationFailed(Exception):
    """Raised when caller authentication fails (fail-closed, no anonymous fallback)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "AUTHENTICATION_FAILED"


DEFAULT_REQUIRED_CLAIMS: tuple[str, ...] = (
    "sub",
    "iss",
    "aud",
    "tenant_id",
    "customer_id",
    "connector_id",
    "scopes",
)


def validate_jwt(  # noqa: PLR0913 - explicit trust parameters, no opaque config object yet
    token: str,
    *,
    key: str | bytes,
    algorithms: Sequence[str] = ("RS256",),
    issuers: Collection[str],
    audiences: Collection[str] = (),
    leeway_seconds: int = 60,
    require_claims: Collection[str] = DEFAULT_REQUIRED_CLAIMS,
) -> dict[str, Any]:
    """Validate a bearer JWT and return its payload as a plain dict.

    Args:
        token: Raw bearer token (without the ``Bearer `` prefix).
        key: PEM public key (asymmetric algorithms) or shared secret.
        algorithms: Allowlisted JWS algorithms; never accept ``none``.
        issuers: Allowlisted ``iss`` values; the token issuer must match one.
        audiences: Allowlisted ``aud`` values; empty disables audience check
            (only acceptable behind mTLS or in tests).
        leeway_seconds: Clock-skew tolerance applied to ``exp``/``nbf``/``iat``.
        require_claims: Claims that must be present for tenant/connector binding.

    Raises:
        AuthenticationFailed: On any validation failure, including expiry,
            wrong issuer/audience, bad signature or missing claims.
    """
    if not token or not token.strip():
        raise AuthenticationFailed("empty bearer token")
    if not issuers and not audiences:
        raise AuthenticationFailed("no trusted issuers or audiences configured")
    if "none" in [alg.lower() for alg in algorithms]:
        raise AuthenticationFailed("algorithm 'none' is never accepted")
    options: dict[str, Any] = {"require": ["exp", "iss"]}
    decode_kwargs: dict[str, Any] = {"leeway": leeway_seconds, "options": options}
    if audiences:
        decode_kwargs["audience"] = list(audiences)
    else:
        options["verify_aud"] = False
    try:
        raw: Any = jwt.decode(token, key=key, algorithms=list(algorithms), **decode_kwargs)
    except jwt.PyJWTError as exc:
        raise AuthenticationFailed(f"token validation failed: {exc}") from exc
    payload: dict[str, Any] = dict(raw)
    if payload.get("iss") not in set(issuers):
        raise AuthenticationFailed("token issuer is not allowlisted")
    missing = [claim for claim in require_claims if claim not in payload]
    if missing:
        raise AuthenticationFailed(f"token misses required claim(s): {', '.join(missing)}")
    return payload
