"""Verify the cloud lab from the deploy runner (stdlib only, no deps).

Checks the connector over its public URL: /health, resolve tuser1 by
sAMAccountName, and a dry-run attribute update (exercises headers,
scope, allowlist and the LDAPS path without writing).
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request

BASE = os.environ["MWA_BASE_URL"].rstrip("/")
SECRET = os.environ["MWA_JWT_SECRET"]
TENANT = os.environ.get("MWA_TENANT_ID", "tenant-lab")
CONNECTOR = os.environ.get("MWA_CONNECTOR_ID", "connector-corp-01")
HTTP_OK = 200


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def token() -> str:
    now = int(time.time())
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64url(
        json.dumps(
            {
                "sub": "identity-agent",
                "iss": "mwa-trusted-agent",
                "aud": "mwa-ad-connector",
                "tenant_id": TENANT,
                "connector_id": CONNECTOR,
                "scopes": ["ad.user.read", "ad.user.attributes.write"],
                "iat": now,
                "exp": now + 900,
                "jti": hashlib.sha256(os.urandom(16)).hexdigest(),
            }
        ).encode()
    )
    data = f"{header}.{payload}"
    sig = _b64url(hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).digest())
    return f"{data}.{sig}"


def call(path: str, body: dict | None, extra: dict | None = None) -> tuple[int, dict]:
    headers = {
        "Authorization": f"Bearer {token()}",
        "Content-Type": "application/json",
        "X-Tenant-ID": TENANT,
        "X-Connector-ID": CONNECTOR,
        "X-Request-Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "X-Request-Nonce": hashlib.sha256(os.urandom(16)).hexdigest(),
        "X-Correlation-ID": hashlib.sha256(os.urandom(16)).hexdigest(),
    }
    headers.update(extra or {})
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(  # noqa: S310
        f"{BASE}{path}",
        data=data,
        headers=headers,
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode() or "{}")
        except ValueError:
            return exc.code, {}


def main() -> int:
    status, health = call("/api/v1/health", None)
    print("health:", status, health.get("status"))
    if status != HTTP_OK or health.get("status") != "HEALTHY":
        return 1
    status, resolved = call(
        "/api/v1/users:resolve",
        {
            "object_type": "USER",
            "domain_id": "domain-corp",
            "identifier_type": "SAM_ACCOUNT_NAME",
            "identifier_value": "tuser1",
        },
    )
    guid = resolved.get("object_guid")
    print("resolve:", status, guid)
    if status != HTTP_OK or not guid:
        return 1
    status, dry = call(
        f"/api/v1/users/{guid}:update-attributes",
        {"attributes": {"givenName": "Mario", "sn": "Rossi"}, "dry_run": True},
        {
            "Idempotency-Key": hashlib.sha256(os.urandom(16)).hexdigest(),
            "X-Ticket-ID": "verify-" + hashlib.sha256(os.urandom(8)).hexdigest()[:8],
        },
    )
    print("dry-run:", status, dry.get("state"), dry.get("disposition"))
    return 0 if status in (200, 202) else 1


if __name__ == "__main__":
    sys.exit(main())
