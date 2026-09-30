"""Diagnostica del mapping entry LDAP -> modello per un utente (read-only).

Esegue una search reale sul DC configurato (stesso filtro del resolver),
poi per ogni entry mostra la forma degli attributi (tipi e lunghezze, non i
valori sensibili) e l'esito di ``map_entry_to_user`` con l'eventuale eccezione.

Usage (PowerShell):
    . C:\\ProgramData\\MWA\\mwa-ad-env.ps1
    uv run python scripts/diag_entry.py jdoe
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ldap3 import SUBTREE  # noqa: E402

from mwa_ad_connector.composition import build_runtime  # noqa: E402
from mwa_ad_connector.config.settings import ConnectorSettings  # noqa: E402
from mwa_ad_connector.infrastructure.ldap.core import _normalize_paged_entry  # noqa: E402
from mwa_ad_connector.infrastructure.ldap.filters import escape_filter_value  # noqa: E402
from mwa_ad_connector.infrastructure.ldap.mappings import map_entry_to_user  # noqa: E402

_ATTRS = [
    "objectGUID",
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "mail",
    "userAccountControl",
    "lockoutTime",
    "pwdLastSet",
    "whenChanged",
    "uSNChanged",
    "memberOf",
    "distinguishedName",
]


def _shape(value: object) -> str:
    """Render a redacted description of an attribute value shape."""
    if isinstance(value, list):
        return f"list[{len(value)}]({', '.join(_shape(v) for v in value[:2])})"
    if isinstance(value, (bytes, bytearray)):
        return f"bytes[{len(value)}]:{bytes(value).hex()[:24]}"
    text = str(value)
    return f"{type(value).__name__}:{text[:48]}"


async def _run(user: str) -> int:
    """Search one user prefix and report attribute shapes plus mapping outcome."""
    settings = ConnectorSettings()  # type: ignore[call-arg]
    runtime = build_runtime(settings)
    try:
        manager = runtime.gateway._manager  # noqa: SLF001 - diagnostic script
        needle = escape_filter_value(user)
        search_filter = (
            f"(&(objectClass=user)(|(sAMAccountName={needle}*)(userPrincipalName={needle}*)(mail={needle}*)))"
        )

        def _op(conn: Any) -> list[dict[str, Any]]:
            conn.search(
                settings.base_dn,
                search_filter,
                search_scope=SUBTREE,
                attributes=_ATTRS,
                paged_size=50,
            )
            return list(conn.response)

        entries, source_dc = await manager.execute(_op)
        print(f"dc={source_dc} entries={len(entries)}")
        for item in entries[:3]:
            normalized = _normalize_paged_entry(item)
            print(f"dn: {normalized['dn']}")
            attributes = normalized["attributes"]
            if isinstance(attributes, dict):
                for key in sorted(str(k) for k in attributes):
                    print(f"  {key}: {_shape(attributes[key])}")
            try:
                mapped = map_entry_to_user(
                    normalized, domain_id=settings.domain_id, source_dc=source_dc, observed_at=datetime.now(UTC)
                )
                print(f"  mapping: OK guid={mapped.object_guid}")
            except Exception as exc:  # noqa: BLE001 - diagnostic boundary
                print(f"  mapping: FAIL {type(exc).__name__}: {exc}")
        return 0
    finally:
        runtime.close()


def main() -> int:
    """Run the entry-shape diagnostic for the user given on the command line."""
    user = sys.argv[1] if len(sys.argv) > 1 else "jdoe"
    return asyncio.run(_run(user))


if __name__ == "__main__":
    raise SystemExit(main())
