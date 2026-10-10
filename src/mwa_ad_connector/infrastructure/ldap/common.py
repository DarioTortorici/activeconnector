"""Shared LDAP adapter constants and entry helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mwa_ad_connector.infrastructure.ldap.error_mapping import map_ldap_result

_USER_ATTRS = [
    "objectGUID",
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "givenName",
    "sn",
    "title",
    "department",
    "company",
    "telephoneNumber",
    "mobile",
    "physicalDeliveryOfficeName",
    "description",
    "mail",
    "userAccountControl",
    "lockoutTime",
    "pwdLastSet",
    "whenChanged",
    "uSNChanged",
    "memberOf",
    "distinguishedName",
]
_GROUP_ATTRS = [
    "objectGUID",
    "sAMAccountName",
    "name",
    "cn",
    "description",
    "mail",
    "groupType",
    "whenChanged",
    "uSNChanged",
    "member",
    "distinguishedName",
]
_OU_ATTRS = ["objectGUID", "ou", "name", "distinguishedName", "whenChanged", "uSNChanged"]
_GUID_ATTRS = ["objectGUID", "distinguishedName"]

_USER_ALLOWLIST = frozenset(
    {
        "displayname",
        "givenname",
        "sn",
        "mail",
        "title",
        "department",
        "company",
        "telephonenumber",
        "mobile",
        "physicaldeliveryofficename",
        "description",
    }
)
_GROUP_ALLOWLIST = frozenset({"description", "mail"})


def _entry_to_dict(entry: Any) -> dict[str, object]:
    result: dict[str, object] = {"dn": str(entry.entry_dn), "attributes": dict(entry.entry_attributes_as_dict)}
    return result


def _check(conn: Any, operation: str) -> None:
    code = int(dict(conn.result).get("result", 80))
    if code != 0:
        mapped = map_ldap_result(code, str(dict(conn.result)), operation)
        raise RuntimeError(f"{mapped.code}: {mapped.remediation}")


def _now() -> datetime:
    return datetime.now(UTC)
