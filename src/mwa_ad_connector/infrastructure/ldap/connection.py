"""LDAPS connection management (fail-closed TLS, pooled, async-friendly)."""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import SecretStr

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(frozen=True)
class LdapConnectionConfig:
    """Connection settings for one AD domain.

    Attributes:
        hosts: DC hostnames/IPs (first is the pinned default).
        port: LDAPS port (default 636).
        use_ssl: Must remain True; plaintext is refused.
        ca_bundle: Path to CA bundle for chain validation.
        bind_user: Service account UPN/DN.
        bind_password: Service account secret.
        connect_timeout: TCP connect timeout seconds.
        operation_timeout: Per-operation timeout seconds.
        pool_size: Max concurrent connections.
        base_dn: Search base DN.
    """

    hosts: tuple[str, ...]
    port: int = 636
    use_ssl: bool = True
    ca_bundle: str | None = None
    bind_user: str = ""
    bind_password: SecretStr | None = None
    connect_timeout: float = 10.0
    operation_timeout: float = 30.0
    pool_size: int = 10
    base_dn: str = ""

    def __post_init__(self) -> None:
        if not self.hosts:
            raise ValueError("at least one DC host is required")
        if not self.use_ssl:
            raise ValueError("plaintext LDAP is forbidden; use_ssl must be True")
        if self.port <= 0 or self.port > 65535:  # noqa: PLR2004
            raise ValueError("invalid port")
        if not self.base_dn:
            raise ValueError("base_dn is required")


@dataclass
class LdapConnectionManager:
    """Manage LDAPS connections with DC pinning and bounded concurrency.

    All blocking ldap3 calls run via :func:`asyncio.to_thread`.
    Kerberos/gMSA without a static secret is documented, not silently used.
    """

    config: LdapConnectionConfig
    _semaphore: asyncio.Semaphore = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._semaphore = asyncio.Semaphore(self.config.pool_size)

    @property
    def pinned_host(self) -> str:
        """Return the default pinned DC host."""
        return self.config.hosts[0]

    def _build_tls(self) -> Any:
        """Build the ldap3 TLS object with fail-closed validation."""
        from ldap3 import Tls  # noqa: PLC0415

        return Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=self.config.ca_bundle,
        )

    def _open_connection(self, host: str) -> Any:
        """Open and bind one synchronous ldap3 connection (blocking).

        Args:
            host: DC to connect to.

        Returns:
            Bound ldap3 Connection.

        Raises:
            RuntimeError: If TLS is not enforced, Kerberos is requested,
                or the bind fails.
        """
        from ldap3 import NTLM, Connection, Server  # noqa: PLC0415

        _ = NTLM  # reference to document auth modes; simple bind under TLS is MVP.
        if not self.config.use_ssl:
            raise RuntimeError("plaintext LDAP refused")
        if not self.config.bind_password:
            raise RuntimeError("Kerberos/gMSA without static secret is not configured in this build")
        server = Server(
            host,
            port=self.config.port,
            use_ssl=True,
            tls=self._build_tls(),
            connect_timeout=self.config.connect_timeout,
        )
        secret = self.config.bind_password.get_secret_value()
        try:
            conn = Connection(
                server,
                user=self.config.bind_user,
                password=secret,
                auto_bind=True,
                receive_timeout=self.config.operation_timeout,
            )
        finally:
            del secret
        logger.info("ldap bind succeeded", extra={"host": host})
        return conn

    async def execute(self, operation: Callable[[Any], T], pinned_dc: str | None = None) -> tuple[T, str]:
        """Run a blocking ldap3 operation on a pinned DC.

        Args:
            operation: Sync callable receiving a bound Connection.
            pinned_dc: DC override; defaults to the pinned host.

        Returns:
            Tuple of (result, source_dc used).
        """
        host = pinned_dc or self.pinned_host
        async with self._semaphore:

            def _run() -> T:
                conn = self._open_connection(host)
                try:
                    return operation(conn)
                finally:
                    try:
                        conn.unbind()
                    except Exception:  # noqa: BLE001
                        logger.warning("ldap unbind failed", extra={"host": host})

            result = await asyncio.to_thread(_run)
            return result, host

    async def check_bind(self, pinned_dc: str | None = None) -> str:
        """Perform a bind-only health check.

        Args:
            pinned_dc: DC override.

        Returns:
            Host that accepted the bind.
        """

        def _noop(conn: Any) -> bool:
            return bool(conn.bound)

        _, host = await self.execute(_noop, pinned_dc)
        return host

    @property
    def is_ldaps_enforced(self) -> bool:
        """Return True when only LDAPS connections are possible."""
        return self.config.use_ssl and self.config.port in (636, 3269)
