"""Manual LDAPS bind spike (lab only, run explicitly, never in CI).

Usage:
    set LAB_LDAPS_HOST=dc01.lab.local
    set LAB_BIND_USER=svc-mwa@lab.local
    set LAB_BIND_PASSWORD=...
    set LAB_BASE_DN=DC=lab,DC=local
    set LAB_CA_BUNDLE=C:\\certs\\lab-ca.pem
    uv run python spikes/ldap/test_bind.py
"""

from __future__ import annotations

import os
import ssl
import sys


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        print(f"missing env {name}", file=sys.stderr)
        raise SystemExit(2)
    return value


def main() -> int:
    host = _env("LAB_LDAPS_HOST")
    user = _env("LAB_BIND_USER")
    base_dn = _env("LAB_BASE_DN")
    ca_bundle = os.environ.get("LAB_CA_BUNDLE")
    password = _env("LAB_BIND_PASSWORD")  # never printed or logged
    _ = base_dn

    from ldap3 import Connection, Server, Tls  # noqa: PLC0415

    for label, ca in (("valid-ca", ca_bundle),):
        _ = label
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca)
        server = Server(host, port=636, use_ssl=True, tls=tls, connect_timeout=10)
        try:
            conn = Connection(server, user=user, password=password, auto_bind=True, receive_timeout=15)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL bind ({label}): {type(exc).__name__}")
            return 1
        print(f"OK bind ({label}): bound={conn.bound} tls={server.ssl}")
        conn.unbind()

    print("NOTE Kerberos/GSSAPI: requires domain-joined host; validate separately with kinit + SASL_GSSAPI.")
    print("NOTE gMSA: run service as gMSA and retry bind without static secret; record in matrix.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
