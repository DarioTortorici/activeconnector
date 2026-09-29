"""LDAP infrastructure package.

Read-only discovery plus write primitives behind
:class:`mwa_ad_connector.application.ports.directory_gateway.DirectoryGateway`.
"""

from mwa_ad_connector.infrastructure.ldap.adapter import LdapDirectoryGateway
from mwa_ad_connector.infrastructure.ldap.connection import LdapConnectionConfig, LdapConnectionManager

__all__ = ["LdapConnectionConfig", "LdapConnectionManager", "LdapDirectoryGateway"]
