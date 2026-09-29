"""Allowlisted LDAP filter construction (RFC 4515 safe).

Only pre-defined query profiles may be used. Raw filter strings from
callers are always rejected to prevent LDAP injection.
"""

from __future__ import annotations

import re
import uuid

_ALLOWED_IDENTIFIER_TYPES = frozenset(
    {"UPN", "SAM_ACCOUNT_NAME", "MAIL", "DISTINGUISHED_NAME", "GROUP_NAME", "OBJECT_GUID"}
)

# Query profiles: (objectClass guard, attribute) pairs. DN/GUID are lookups, not filters.
_QUERY_PROFILES: dict[str, dict[str, str]] = {
    "USER_BY_UPN": {"object_class": "user", "attribute": "userPrincipalName"},
    "USER_BY_SAM": {"object_class": "user", "attribute": "sAMAccountName"},
    "USER_BY_MAIL": {"object_class": "user", "attribute": "mail"},
    "USER_BY_GUID": {"object_class": "user", "attribute": "objectGUID"},
    "GROUP_BY_NAME": {"object_class": "group", "attribute": "sAMAccountName"},
    "GROUP_BY_MAIL": {"object_class": "group", "attribute": "mail"},
    "GROUP_BY_GUID": {"object_class": "group", "attribute": "objectGUID"},
    "OU_BY_GUID": {"object_class": "organizationalUnit", "attribute": "objectGUID"},
}

_MAX_VALUE_LENGTH = 1024


def escape_filter_value(value: str) -> str:
    """Escape a filter assertion value per RFC 4515.

    Args:
        value: Raw assertion value.

    Returns:
        Escaped value safe for embedding in a filter template.

    Raises:
        ValueError: If the value is empty or exceeds the length limit.
    """
    if not value:
        raise ValueError("filter value must not be empty")
    if len(value) > _MAX_VALUE_LENGTH:
        raise ValueError("filter value exceeds length limit")
    out: list[str] = []
    for ch in value:
        if ch == "*":
            out.append(r"\2a")
        elif ch == "(":
            out.append(r"\28")
        elif ch == ")":
            out.append(r"\29")
        elif ch == "\\":
            out.append(r"\5c")
        elif ch == "\x00":
            out.append(r"\00")
        else:
            out.append(ch)
    return "".join(out)


def reject_raw_filter(filter_text: str) -> None:
    """Reject any caller-supplied raw filter string.

    Args:
        filter_text: Untrusted filter text.

    Raises:
        ValueError: Always; raw filters are never allowed.
    """
    raise ValueError(f"raw LDAP filters are forbidden (got {len(filter_text)} chars)")


def build_guid_filter(object_guid: uuid.UUID) -> str:
    """Build an objectGUID equality filter for the given GUID.

    Args:
        object_guid: Stable object identifier.

    Returns:
        Filter string with GUID bytes escaped as ``\\xx`` sequences.
    """
    raw = object_guid.bytes_le
    escaped = "".join(f"\\{b:02x}" for b in raw)
    return f"(objectGUID={escaped})"


def build_identifier_filter(identifier_type: str, identifier_value: str) -> str:
    """Build a filter for an allowlisted identifier type.

    Args:
        identifier_type: One of UPN, SAM_ACCOUNT_NAME, MAIL, GROUP_NAME, OBJECT_GUID.
        identifier_value: Identifier value (GUID string for OBJECT_GUID).

    Returns:
        LDAP filter string.

    Raises:
        ValueError: If the identifier type is not allowlisted.
    """
    normalized = identifier_type.upper()
    if normalized not in _ALLOWED_IDENTIFIER_TYPES:
        raise ValueError(f"identifier type not allowlisted: {identifier_type}")
    if normalized == "DISTINGUISHED_NAME":
        raise ValueError("DISTINGUISHED_NAME uses base-object lookup, not a filter")
    if normalized == "OBJECT_GUID":
        return build_guid_filter(uuid.UUID(identifier_value))
    mapping = {
        "UPN": ("user", "userPrincipalName"),
        "SAM_ACCOUNT_NAME": ("user", "sAMAccountName"),
        "MAIL": ("user", "mail"),
        "GROUP_NAME": ("group", "sAMAccountName"),
    }
    if normalized == "GROUP_NAME":
        esc = escape_filter_value(identifier_value)
        return f"(&(objectClass=group)(|(sAMAccountName={esc})(name={esc})))"
    object_class, attribute = mapping[normalized]
    esc = escape_filter_value(identifier_value)
    return f"(&(objectClass={object_class})({attribute}={esc}))"


def build_query_profile_filter(profile: str, value: str) -> str:
    """Build a filter from a pre-defined query profile.

    Args:
        profile: Profile name (e.g. ``USER_BY_UPN``).
        value: Lookup value.

    Returns:
        LDAP filter string.

    Raises:
        ValueError: If the profile is unknown.
    """
    spec = _QUERY_PROFILES.get(profile)
    if spec is None:
        raise ValueError(f"unknown query profile: {profile}")
    attribute = spec["attribute"]
    if attribute == "objectGUID":
        return build_guid_filter(uuid.UUID(value))
    esc = escape_filter_value(value)
    return f"(&(objectClass={spec['object_class']})({attribute}={esc}))"


def list_query_profiles() -> dict[str, dict[str, str]]:
    """Return a copy of the allowlisted query-profile table.

    Returns:
        Mapping of profile name to object-class/attribute spec.
    """
    return dict(_QUERY_PROFILES)


_DN_PATTERN = re.compile(r"^(?:[A-Za-z]+=[^,]+)(?:,[A-Za-z]+=[^,]+)*$")


def validate_dn_syntax(dn: str) -> str:
    """Validate DN syntax superficially (not existence).

    Args:
        dn: Distinguished name.

    Returns:
        The DN unchanged.

    Raises:
        ValueError: If the DN is empty, too long, or malformed.
    """
    if not dn or len(dn) > 2048:  # noqa: PLR2004
        raise ValueError("DN must be 1..2048 chars")
    if not _DN_PATTERN.match(dn.strip()):
        raise ValueError("malformed DN syntax")
    return dn.strip()
