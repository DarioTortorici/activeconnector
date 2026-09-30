"""Diagnostica LDAPS verso il DC configurato (read-only).

Esegue tre passi con esito esplicito, usando le variabili ``MWA_AD_*``:

1. TCP connect su ``dc_host:dc_port``
2. TLS handshake con il trust store configurato (mostra subject/issuer del cert)
3. Bind LDAP con le credenziali configurate (mostra solo esito e messaggio)

La password non viene mai stampata. Nessuna operazione LDAP oltre il bind.

Usage (PowerShell):
    . C:\\ProgramData\\MWA\\mwa-ad-env.ps1
    uv run python scripts/diag_ldaps.py
"""

from __future__ import annotations

import socket
import ssl
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mwa_ad_connector.config.settings import ConnectorSettings  # noqa: E402


def _redact_password(message: str, settings: ConnectorSettings) -> str:
    """Remove the configured bind password from an error message, if present."""
    if settings.bind_password is None:
        return message
    secret = settings.bind_password.get_secret_value()
    return message.replace(secret, "***") if secret else message


def _tls_step(settings: ConnectorSettings) -> tuple[bool, str]:
    """Run the strict TLS handshake against the pinned DC."""
    try:
        context = ssl.create_default_context(cafile=settings.trust_store_path)
        with (
            socket.create_connection(
                (settings.dc_host, settings.dc_port), timeout=settings.ldap_connect_timeout_seconds
            ) as raw,
            context.wrap_socket(raw, server_hostname=settings.dc_host) as tls,
        ):
            info: dict[str, Any] = tls.getpeercert()
            subject: dict[str, str] = dict(x[0] for x in info.get("subject", ()))
            issuer: dict[str, str] = dict(x[0] for x in info.get("issuer", ()))
            expires = info.get("notAfter")
            return True, f"subject={subject.get('commonName')} issuer={issuer.get('commonName')} scade={expires}"
    except Exception as exc:  # noqa: BLE001 - diagnostic boundary.
        return False, f"{type(exc).__name__}: {exc}"


def _bind_step(settings: ConnectorSettings) -> tuple[bool, str]:
    """Run the LDAP simple bind over LDAPS."""
    try:
        import ldap3  # noqa: PLC0415 - only needed by this diagnostic.

        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=settings.trust_store_path)
        server = ldap3.Server(
            settings.dc_host,
            port=settings.dc_port,
            use_ssl=True,
            tls=tls,
            connect_timeout=settings.ldap_connect_timeout_seconds,
        )
        password = settings.bind_password.get_secret_value() if settings.bind_password else ""
        conn = ldap3.Connection(
            server,
            user=settings.bind_user or "",
            password=password,
            auto_bind=True,
            receive_timeout=settings.ldap_operation_timeout_seconds,
        )
        result = str(conn.result)
        conn.unbind()
        return True, f"result={result}"
    except Exception as exc:  # noqa: BLE001 - diagnostic boundary.
        return False, _redact_password(f"{type(exc).__name__}: {exc}", settings)


def main() -> int:
    """Run the three-step LDAPS diagnostic.

    Returns:
        Process exit code (0 all steps passed, 1 first failure).
    """
    settings = ConnectorSettings()  # type: ignore[call-arg]
    print(f"DC            : {settings.dc_host}:{settings.dc_port} (ldaps={settings.use_ldaps})")
    trust = settings.trust_store_path
    print(f"Trust store   : {trust} (esiste={bool(trust and Path(trust).is_file())})")

    try:
        with socket.create_connection(
            (settings.dc_host, settings.dc_port), timeout=settings.ldap_connect_timeout_seconds
        ):
            print("[1/3] TCP connect : OK")
    except socket.gaierror as exc:
        print(f"[1/3] TCP connect : FAIL DNS {type(exc).__name__}: {exc}")
        print("      Il nome del DC non risolve da questo host: aggiungi il FQDN al file hosts")
        print(r"      (C:\Windows\System32\drivers\etc\hosts) o configura il DNS del dominio.")
        return 1
    except Exception as exc:  # noqa: BLE001 - diagnostic boundary.
        print(f"[1/3] TCP connect : FAIL {type(exc).__name__}: {exc}")
        print("      Causa probabile: firewall/routing verso la porta 636 dal host connettore.")
        return 1

    tls_ok, tls_detail = _tls_step(settings)
    print(f"[2/3] TLS strict  : {'OK ' + tls_detail if tls_ok else 'FAIL ' + tls_detail}")
    if not tls_ok:
        print("      Verifica: PEM corretto nel trust store, SAN del certificato, catena self-signed in Root sul DC.")
        return 1

    bind_ok, bind_detail = _bind_step(settings)
    print(f"[3/3] LDAP bind   : {'OK ' + bind_detail if bind_ok else 'FAIL ' + bind_detail}")
    if not bind_ok:
        print("      Se compare 'data 52e/525/532/775' e' un problema di credenziali/account (mappa in error_mapping).")
        return 1

    print("Diagnostica superata: TCP + TLS + bind OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
