"""Mint an HS256 caller JWT for manual/lab testing (secret never printed).

Usage (PowerShell):
    $env:MWA_AD_JWT_SECRET = "lab-only-jwt-secret"
    uv run python scripts/mint_token.py --subject ops@lab.example.test `
        --tenant-id tenant-lab --customer-id customer-lab `
        --connector-id connector-lab-01 `
        --scopes ad.user.read,ad.group.member.write --ttl-seconds 900

Only the token is written to stdout; the signing secret is read from
``MWA_AD_JWT_SECRET`` and is never logged or echoed. Exit code is non-zero
when the secret is missing.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

import jwt

DEFAULT_ISSUER = "mwa-trusted-agent"
DEFAULT_AUDIENCE = "mwa-ad-connector"
DEFAULT_TTL_SECONDS = 900


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Args:
        argv: Optional argument list for testing.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(description="Mint an HS256 caller JWT for the MWA AD connector.")
    parser.add_argument("--subject", required=True, help="Token subject (e.g. operator identity).")
    parser.add_argument("--tenant-id", required=True, help="Tenant boundary (must match X-Tenant-ID).")
    parser.add_argument("--customer-id", required=True, help="Customer boundary.")
    parser.add_argument("--connector-id", required=True, help="Connector boundary (must match X-Connector-ID).")
    parser.add_argument("--scopes", default="", help="Comma-separated caller scopes.")
    parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS, help="Token lifetime in seconds.")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER, help="Token issuer (must match MWA_AD_JWT_ISSUER).")
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE, help="Token audience (must match MWA_AD_JWT_AUDIENCE).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Mint and print the token.

    Args:
        argv: Optional argument list for testing.

    Returns:
        Process exit code (0 minted, 1 missing secret).
    """
    args = parse_args(argv)
    secret = os.environ.get("MWA_AD_JWT_SECRET", "")
    if not secret:
        sys.stderr.write("MWA_AD_JWT_SECRET is not set; refusing to mint an unsigned token.\n")
        return 1
    now = datetime.now(UTC)
    payload = {
        "sub": args.subject,
        "iss": args.issuer,
        "aud": args.audience,
        "exp": now + timedelta(seconds=args.ttl_seconds),
        "iat": now,
        "jti": uuid.uuid4().hex,
        "tenant_id": args.tenant_id,
        "customer_id": args.customer_id,
        "connector_id": args.connector_id,
        "scopes": [scope.strip() for scope in args.scopes.split(",") if scope.strip()],
        "roles": ["operator"],
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    sys.stdout.write(f"{token}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
