"""Unit: LDAPS connection config invariants and fail-closed bind path."""

from __future__ import annotations

import pytest

from mwa_ad_connector.infrastructure.ldap.connection import (
    LdapConnectionConfig,
    LdapConnectionManager,
)


def test_config_rejects_missing_host_and_base_dn() -> None:
    with pytest.raises(ValueError):
        LdapConnectionConfig(hosts=(), base_dn="DC=lab,DC=local")
    with pytest.raises(ValueError):
        LdapConnectionConfig(hosts=("dc01.lab.local",), base_dn="")


def test_config_rejects_plaintext() -> None:
    with pytest.raises(ValueError):
        LdapConnectionConfig(hosts=("dc01.lab.local",), base_dn="DC=lab,DC=local", use_ssl=False)


def test_open_connection_requires_password() -> None:
    """Simple bind without a password fails closed before any network I/O."""
    manager = LdapConnectionManager(LdapConnectionConfig(hosts=("dc01.lab.local",), base_dn="DC=lab,DC=local"))
    with pytest.raises(RuntimeError, match="bind_password"):
        manager._open_connection("dc01.lab.local")  # noqa: SLF001 - explicit fail-closed seam.
