"""LDAP DirectoryGateway implementation over ldap3 (async wrapper).

Combines the read and write mixins over a pinned-DC core. All blocking
ldap3 calls run via :func:`asyncio.to_thread`. Commit and read-after-write
share the same pinned host, exposed via :attr:`source_dc`.
"""

from __future__ import annotations

from mwa_ad_connector.domain.enums import IdentifierType
from mwa_ad_connector.infrastructure.ldap.common import _GROUP_ALLOWLIST, _USER_ALLOWLIST
from mwa_ad_connector.infrastructure.ldap.reads import LdapAdapterReads
from mwa_ad_connector.infrastructure.ldap.writes import LdapAdapterWrites


class LdapDirectoryGateway(LdapAdapterReads, LdapAdapterWrites):
    """DirectoryGateway backed by ldap3 over LDAPS, pinned to one DC."""

    @staticmethod
    def user_allowlist() -> frozenset[str]:
        """Return the user attribute allowlist."""
        return _USER_ALLOWLIST

    @staticmethod
    def group_allowlist() -> frozenset[str]:
        """Return the group attribute allowlist."""
        return _GROUP_ALLOWLIST

    @staticmethod
    def identifier_kind() -> type[IdentifierType]:
        """Return the allowlisted identifier enum (for resolver reference)."""
        return IdentifierType
