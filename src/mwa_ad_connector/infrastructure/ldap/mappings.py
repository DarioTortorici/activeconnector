"""Map LDAP entries to typed domain objects.

Conversions are lossless where possible; secrets are never included.
Missing schema-mandatory attributes raise ``ValueError`` (unexpected
schema) instead of fabricating empty domain values.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
from datetime import UTC, datetime, timedelta

from mwa_ad_connector.domain.objects import DirectoryGroup, DirectoryUser, OrganizationalUnit

ACCOUNTDISABLE = 0x0002
LOCKOUT = 0x0010

# groupType scope bits (AD schema).
_SCOPE_BITS = ((0x00000001, "Builtin"), (0x00000002, "Global"), (0x00000004, "DomainLocal"), (0x00000008, "Universal"))

# Attributes that must never appear in redacted views / evidence.
_SECRET_ATTRS = frozenset({"unicodepwd", "userpassword", "password", "krb5key"})

_USER_ALLOWLIST = frozenset(
    {
        "cn",
        "displayname",
        "givenname",
        "sn",
        "samaccountname",
        "userprincipalname",
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

_GROUP_ALLOWLIST = frozenset({"cn", "name", "samaccountname", "description", "mail", "grouptype"})

_AD_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def guid_bytes_le_to_uuid(raw: bytes) -> uuid.UUID:
    """Convert AD objectGUID bytes (mixed-endian) to UUID.

    Args:
        raw: 16 raw bytes from the LDAP entry.

    Returns:
        Parsed UUID.

    Raises:
        ValueError: If the byte string is not 16 bytes.
    """
    if len(raw) != 16:  # noqa: PLR2004
        raise ValueError("objectGUID must be 16 bytes")
    return uuid.UUID(bytes_le=raw)


def sid_bytes_to_str(raw: bytes) -> str:
    """Convert a binary SID to string form (S-1-...).

    Args:
        raw: Binary SID.

    Returns:
        String SID.

    Raises:
        ValueError: If the SID is malformed.
    """
    if len(raw) < 8:  # noqa: PLR2004
        raise ValueError("SID too short")
    revision, sub_count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    if len(raw) != 8 + 4 * sub_count:
        raise ValueError("SID length mismatch")
    sub_auths = [str(struct.unpack_from("<I", raw, 8 + 4 * i)[0]) for i in range(sub_count)]
    return f"S-{revision}-{authority}-{'-'.join(sub_auths)}" if sub_auths else f"S-{revision}-{authority}"


def filetime_to_datetime(value: int) -> datetime | None:
    """Convert AD FILETIME (100ns since 1601) to datetime.

    Args:
        value: FILETIME integer.

    Returns:
        Aware datetime, or None for never (0 / 0x7FFFFFFFFFFFFFFF).
    """
    if value in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    try:
        return _AD_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def uac_to_enabled_locked(user_account_control: int) -> tuple[bool, bool]:
    """Derive enabled/locked flags from userAccountControl.

    Args:
        user_account_control: Raw bitmask.

    Returns:
        Tuple of (enabled, locked).
    """
    enabled = not bool(user_account_control & ACCOUNTDISABLE)
    locked = bool(user_account_control & LOCKOUT)
    return enabled, locked


def group_type_to_scope_category(group_type: int) -> tuple[str, str]:
    """Derive scope/category labels from the groupType bitmask.

    Args:
        group_type: Raw groupType value (signed 32-bit).

    Returns:
        Tuple of (scope, category).
    """
    unsigned = group_type & 0xFFFFFFFF
    scope = next((label for bit, label in _SCOPE_BITS if unsigned & bit), "Unknown")
    category = "Security" if unsigned & 0x80000000 else "Distribution"
    return scope, category


def build_version_token(when_changed: str | None, usn_changed: str | None, usn_created: str | None = None) -> str:
    """Build an opaque concurrency token from replication attributes.

    Args:
        when_changed: whenChanged value.
        usn_changed: uSNChanged value.
        usn_created: Optional uSNCreated value.

    Returns:
        Hex digest token.
    """
    material = f"{when_changed or ''}|{usn_changed or ''}|{usn_created or ''}".encode()
    return hashlib.sha256(material).hexdigest()[:32]


def redacted_attributes_view(attributes: dict[str, list[str]], allowlist: frozenset[str]) -> dict[str, list[str]]:
    """Return an allowlisted, secret-free attribute view.

    Args:
        attributes: Raw multi-valued attributes.
        allowlist: Lower-cased allowed attribute names.

    Returns:
        Filtered attribute mapping.
    """
    out: dict[str, list[str]] = {}
    for name, values in attributes.items():
        lowered = name.lower()
        if lowered in _SECRET_ATTRS:
            continue
        if lowered not in allowlist:
            continue
        out[name] = list(values)
    return out


def _first(values: object) -> str | None:
    if isinstance(values, (list, tuple)) and values:
        first = values[0]
        if isinstance(first, bytes):
            return first.decode("utf-8", "replace")
        return str(first)
    if isinstance(values, bytes):
        return values.decode("utf-8", "replace")
    if values is None:
        return None
    return str(values)


def _require(value: str | None, attribute: str) -> str:
    if not value:
        raise ValueError(f"unexpected schema: {attribute} missing in LDAP entry")
    return value


def _entry_guid(attrs: dict[str, object]) -> uuid.UUID:
    raw_guid = attrs.get("objectGUID")
    guid_bytes = raw_guid[0] if isinstance(raw_guid, list) and raw_guid else raw_guid
    if isinstance(guid_bytes, str):
        guid_bytes = guid_bytes.encode("latin1")
    if not isinstance(guid_bytes, (bytes, bytearray)):
        raise ValueError("unexpected schema: objectGUID missing in LDAP entry")
    return guid_bytes_le_to_uuid(bytes(guid_bytes))


def _flatten(attrs: dict[str, object]) -> dict[str, list[str]]:
    flat: dict[str, list[str]] = {}
    for key, val in attrs.items():
        items = val if isinstance(val, list) else [val]
        flat[key] = [v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v) for v in items]
    return flat


def map_entry_to_user(
    entry: dict[str, object],
    *,
    domain_id: str,
    source_dc: str,
    observed_at: datetime,
) -> DirectoryUser:
    """Map a raw LDAP entry dict to a DirectoryUser.

    Args:
        entry: Raw entry with ``dn`` and ``attributes`` keys.
        domain_id: Owning domain id.
        source_dc: DC hostname that served the read.
        observed_at: Observation timestamp.

    Returns:
        Canonical ``DirectoryUser``.

    Raises:
        TypeError: If attributes are not a mapping.
        ValueError: If schema-mandatory attributes are missing.
    """
    attrs = entry.get("attributes", {})
    if not isinstance(attrs, dict):
        raise TypeError("LDAP entry attributes must be a mapping")
    uac = int(_first(attrs.get("userAccountControl")) or 0)
    enabled, locked = uac_to_enabled_locked(uac)
    pwd_raw = _first(attrs.get("pwdLastSet"))
    pwd_last_set = filetime_to_datetime(int(pwd_raw)) if pwd_raw and pwd_raw.lstrip("-").isdigit() else None
    return DirectoryUser(
        object_guid=_entry_guid(attrs),
        distinguished_name=_require(str(entry.get("dn", "")) or None, "distinguishedName"),
        domain_id=domain_id,
        sam_account_name=_require(_first(attrs.get("sAMAccountName")), "sAMAccountName"),
        user_principal_name=_first(attrs.get("userPrincipalName")),
        display_name=_first(attrs.get("displayName")),
        enabled=enabled,
        locked=locked,
        pwd_last_set=pwd_last_set,
        member_of_guids=[],
        attributes=redacted_attributes_view(_flatten(attrs), _USER_ALLOWLIST),
        version_token=build_version_token(_first(attrs.get("whenChanged")), _first(attrs.get("uSNChanged"))),
        source_dc=source_dc,
        observed_at=observed_at,
    )


def map_entry_to_group(
    entry: dict[str, object],
    *,
    domain_id: str,
    source_dc: str,
    observed_at: datetime,
) -> DirectoryGroup:
    """Map a raw LDAP entry dict to a DirectoryGroup.

    Args:
        entry: Raw entry with ``dn`` and ``attributes`` keys.
        domain_id: Owning domain id.
        source_dc: DC hostname that served the read.
        observed_at: Observation timestamp.

    Returns:
        Canonical ``DirectoryGroup``.

    Raises:
        TypeError: If attributes are not a mapping.
        ValueError: If schema-mandatory attributes are missing.
    """
    attrs = entry.get("attributes", {})
    if not isinstance(attrs, dict):
        raise TypeError("LDAP entry attributes must be a mapping")
    scope, category = group_type_to_scope_category(int(_first(attrs.get("groupType")) or 0))
    return DirectoryGroup(
        object_guid=_entry_guid(attrs),
        distinguished_name=_require(str(entry.get("dn", "")) or None, "distinguishedName"),
        domain_id=domain_id,
        sam_account_name=_require(_first(attrs.get("sAMAccountName")), "sAMAccountName"),
        name=_require(_first(attrs.get("name")) or _first(attrs.get("cn")), "name/cn"),
        group_scope=scope,
        group_category=category,
        member_guids=[],
        is_privileged=False,
        protection_reasons=[],
        version_token=build_version_token(_first(attrs.get("whenChanged")), _first(attrs.get("uSNChanged"))),
        source_dc=source_dc,
        observed_at=observed_at,
    )


def map_entry_to_ou(
    entry: dict[str, object],
    *,
    domain_id: str,
    source_dc: str,
    observed_at: datetime,
) -> OrganizationalUnit:
    """Map a raw LDAP entry dict to an OrganizationalUnit.

    Args:
        entry: Raw entry with ``dn`` and ``attributes`` keys.
        domain_id: Owning domain id.
        source_dc: DC hostname that served the read.
        observed_at: Observation timestamp.

    Returns:
        Canonical ``OrganizationalUnit``.

    Raises:
        TypeError: If attributes are not a mapping.
        ValueError: If schema-mandatory attributes are missing.
    """
    attrs = entry.get("attributes", {})
    if not isinstance(attrs, dict):
        raise TypeError("LDAP entry attributes must be a mapping")
    dn = _require(str(entry.get("dn", "")) or None, "distinguishedName")
    parent = dn.split(",", 1)[1] if "," in dn else dn
    return OrganizationalUnit(
        object_guid=_entry_guid(attrs),
        distinguished_name=dn,
        domain_id=domain_id,
        name=_require(_first(attrs.get("ou")) or _first(attrs.get("name")), "ou/name"),
        parent_dn=parent,
        child_count=0,
        version_token=build_version_token(_first(attrs.get("whenChanged")), _first(attrs.get("uSNChanged"))),
        source_dc=source_dc,
        observed_at=observed_at,
    )
