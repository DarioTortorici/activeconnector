"""Manual paged-search spike (lab only, run explicitly, never in CI).

Usage:
    set LAB_LDAPS_HOST=dc01.lab.local
    ... (same env as test_bind.py)
    uv run python spikes/ldap/test_paging.py --page-size 100 --filter-profile USER_BY_SAM --value "*"
"""

from __future__ import annotations

import argparse
import os
import ssl
import sys


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name, default)
    if not value:
        print(f"missing env {name}", file=sys.stderr)
        raise SystemExit(2)
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--filter-profile", default="USER_BY_SAM")
    parser.add_argument("--value", default="*")
    args = parser.parse_args()

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    from ldap3 import SUBTREE, Connection, Server, Tls  # noqa: PLC0415

    from mwa_ad_connector.infrastructure.ldap.controls import PagedSearchState  # noqa: PLC0415
    from mwa_ad_connector.infrastructure.ldap.filters import build_query_profile_filter  # noqa: PLC0415

    host = _env("LAB_LDAPS_HOST")
    user = _env("LAB_BIND_USER")
    password = _env("LAB_BIND_PASSWORD")  # never printed or logged
    base_dn = _env("LAB_BASE_DN")
    ca_bundle = os.environ.get("LAB_CA_BUNDLE")

    if args.value == "*":
        search_filter = "(objectClass=user)"
        print("WARN: using broad filter for paging volume; lab only.")
    else:
        search_filter = build_query_profile_filter(args.filter_profile, args.value)

    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_bundle)
    server = Server(host, port=636, use_ssl=True, tls=tls, connect_timeout=10)
    conn = Connection(server, user=user, password=password, auto_bind=True, receive_timeout=30)
    try:
        state = PagedSearchState()
        gen = conn.extend.standard.paged_search(
            base_dn,
            search_filter,
            SUBTREE,
            attributes=["objectGUID", "distinguishedName"],
            paged_size=args.page_size,
            generator=True,
        )
        page: list[str] = []
        for entry in gen:
            if not getattr(entry, "entry_dn", None):
                continue
            page.append(str(entry.entry_dn))
            if len(page) >= args.page_size:
                state.advance(b"page", page)
                page = []
        state.advance(b"", page)
        print(f"OK paging: pages={state.pages_returned} entries={state.entries_seen} duplicates=0")
        return 0
    except ValueError as exc:
        print(f"FAIL paging: {exc}")
        return 1
    finally:
        conn.unbind()


if __name__ == "__main__":
    raise SystemExit(main())
