"""Protected-target guards: privileged groups and accounts (Step 7).

These checks apply *before* any LDAP write. They complement (never
replace) the minimum AD ACLs of the service account: even with a
sufficient ACL, a protected target is denied at application policy level.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping

# Conservative seed of domain-relative RIDs that always denote privilege.
# Routine groups such as Domain Users (513) are deliberately excluded.
PRIVILEGED_RIDS: frozenset[int] = frozenset(
    {
        500,  # Administrator
        502,  # KRBTGT
        512,  # Domain Admins
        516,  # Domain Controllers
        518,  # Schema Admins
        519,  # Enterprise Admins
        520,  # Group Policy Creator Owners
        526,  # Key Admins
        527,  # Enterprise Key Admins
        569,  # Cryptographic Operators
    }
)

# Well-known builtin SIDs (S-1-5-32-*) that always denote privilege.
PRIVILEGED_SID_SUFFIXES: frozenset[str] = frozenset(
    {
        "S-1-5-32-544",  # Administrators
        "S-1-5-32-548",  # Account Operators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-550",  # Print Operators
        "S-1-5-32-551",  # Backup Operators
        "S-1-5-32-552",  # Replicators
    }
)

# Privileged group common names / sAMAccountNames (compared case-insensitively).
PRIVILEGED_GROUP_NAMES: frozenset[str] = frozenset(
    {
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "account operators",
        "backup operators",
        "server operators",
        "print operators",
        "dnsadmins",
        "group policy creator owners",
        "key admins",
        "enterprise key admins",
        "protected users",
        "domain controllers",
    }
)


def _sid_rid(object_sid: str) -> int | None:
    """Extract the trailing RID from an objectSID string, if parseable."""
    tail = object_sid.strip().upper().rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() else None


def _cn_of(dn: str) -> str:
    """Extract the CN (or first RDN value) of a DN, lowercased."""
    first = dn.split(",", 1)[0]
    _, _, value = first.partition("=")
    return value.strip().lower()


def _is_privileged_name(name: str | None) -> bool:
    if name is None:
        return False
    return name.strip().lower() in PRIVILEGED_GROUP_NAMES


def _is_privileged_sid(object_sid: str | None) -> bool:
    if not object_sid:
        return False
    sid = object_sid.strip().upper()
    if sid in PRIVILEGED_SID_SUFFIXES:
        return True
    rid = _sid_rid(sid)
    return rid is not None and rid in PRIVILEGED_RIDS


def is_protected_group(
    *,
    dn: str | None = None,
    sam_account_name: str | None = None,
    name: str | None = None,
    object_sid: str | None = None,
    member_of: Collection[str] = (),
) -> str | None:
    """Return None when the group is operable, otherwise a deny reason.

    A group is protected when its name matches a known privileged group,
    its SID carries a privileged RID/suffix, or it nests (``member_of``)
    a privileged group.
    """
    if _is_privileged_name(name) or _is_privileged_name(sam_account_name):
        return f"group {name or sam_account_name!r} is a known privileged group"
    if dn is not None and _is_privileged_name(_cn_of(dn)):
        return f"group DN {dn!r} belongs to a known privileged group"
    if _is_privileged_sid(object_sid):
        return f"group SID {object_sid!r} is a known privileged SID"
    for parent in member_of:
        if _is_privileged_name(_cn_of(parent)):
            return f"group nests privileged group {parent!r} via memberOf"
    return None


def is_protected_user(
    *,
    dn: str | None = None,
    sam_account_name: str | None = None,
    is_service_account: bool = False,
    admin_count: int | None = None,
    member_of: Collection[str] = (),
) -> str | None:
    """Return None when the account is operable, otherwise a deny reason.

    An account is protected when it is flagged as a service account
    (name ends with ``$`` or explicit flag), carries ``adminCount=1``
    (AdminSDHolder-protected), or nests a privileged group.
    """
    if is_service_account or (sam_account_name or "").endswith("$"):
        return f"account {sam_account_name or dn!r} is a service account"
    if admin_count == 1:
        return f"account {sam_account_name or dn!r} is AdminSDHolder-protected (adminCount=1)"
    for parent in member_of:
        if _is_privileged_name(_cn_of(parent)):
            return f"account is a member of privileged group {parent!r}"
    return None


def check_target(kind: str, info: Mapping[str, object]) -> str | None:
    """Dispatch protected-target evaluation by object kind.

    Args:
        kind: ``"user"``, ``"group"`` or ``"ou"`` (OUs are never
            protected by this module; OU scope is enforced by scopes).
        info: Target attributes (``dn``, ``sam_account_name``, ``name``,
            ``object_sid``, ``member_of``, ``is_service_account``,
            ``admin_count``).

    Returns:
        None when operable, otherwise an explainable deny reason.
    """
    member_of = info.get("member_of", ())
    parents: Collection[str] = member_of if isinstance(member_of, Collection) else ()
    admin_raw = info.get("admin_count")
    admin_count = admin_raw if isinstance(admin_raw, int) else None
    if kind == "group":
        sid = info.get("object_sid")
        return is_protected_group(
            dn=_as_str(info.get("dn")),
            sam_account_name=_as_str(info.get("sam_account_name")),
            name=_as_str(info.get("name")),
            object_sid=sid if isinstance(sid, str) else None,
            member_of=parents,
        )
    if kind == "user":
        return is_protected_user(
            dn=_as_str(info.get("dn")),
            sam_account_name=_as_str(info.get("sam_account_name")),
            is_service_account=bool(info.get("is_service_account", False)),
            admin_count=admin_count,
            member_of=parents,
        )
    return None


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None
