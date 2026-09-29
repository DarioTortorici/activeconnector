"""Staged LDAP modify helpers (Add/Delete/Replace, unicodePwd, UAC, ModifyDN)."""

from __future__ import annotations

from pydantic import SecretStr

ACCOUNTDISABLE = 0x0002


def encode_unicode_pwd(password: SecretStr) -> bytes:
    """Encode a password for the unicodePwd attribute.

    Args:
        password: Cleartext password (held in a SecretStr).

    Returns:
        Quoted UTF-16LE bytes as required by AD.
    """
    secret = password.get_secret_value()
    try:
        return f'"{secret}"'.encode("utf-16-le")
    finally:
        del secret


def staged_modify(
    old: dict[str, list[str]], new: dict[str, list[str]], allowlist: frozenset[str]
) -> list[tuple[str, str, list[str]]]:
    """Compute a minimal Add/Delete/Replace diff for allowlisted attributes.

    Multi-valued attributes are handled as ordered sets.

    Args:
        old: Current values per attribute.
        new: Desired values per attribute.
        allowlist: Lower-cased allowed attribute names.

    Returns:
        List of (attribute, operation, values) with operation in
        ADD/DELETE/REPLACE.

    Raises:
        ValueError: If a non-allowlisted attribute is requested.
    """
    ops: list[tuple[str, str, list[str]]] = []
    for name in new:
        if name.lower() not in allowlist:
            raise ValueError(f"attribute not allowlisted: {name}")
    for name, desired in new.items():
        current = old.get(name, [])
        if set(current) == set(desired) and len(current) == len(desired):
            continue
        if not current and desired:
            ops.append((name, "ADD", list(desired)))
        elif current and not desired:
            ops.append((name, "DELETE", []))
        else:
            ops.append((name, "REPLACE", list(desired)))
    return ops


def build_lockout_reset() -> list[tuple[str, str, list[int]]]:
    """Build the lockoutTime=0 unlock modification.

    Returns:
        Single REPLACE operation for lockoutTime.
    """
    return [("lockoutTime", "REPLACE", [0])]


def uac_bit_safe(current: int, enable: bool | None = None, lock_hint: bool = False) -> int:
    """Update userAccountControl preserving unrelated bits.

    Args:
        current: Current bitmask.
        enable: True to clear ACCOUNTDISABLE, False to set it, None to keep.
        lock_hint: Reserved; lock state is not set via UAC.

    Returns:
        New bitmask.
    """
    _ = lock_hint
    if enable is True:
        return current & ~ACCOUNTDISABLE
    if enable is False:
        return current | ACCOUNTDISABLE
    return current


def pwd_last_set_force_change(force: bool) -> int:
    """Return the pwdLastSet value for force-change semantics.

    Args:
        force: True sets 0 (must change at next logon).

    Returns:
        0 when forcing, -1 when clearing the flag.
    """
    return 0 if force else -1


def build_modify_dn(new_rdn: str, new_superior: str | None = None, delete_old_rdn: bool = True) -> dict[str, object]:
    """Build ModifyDN parameters for rename/move.

    Args:
        new_rdn: New relative DN (e.g. ``CN=New Name``).
        new_superior: Destination container DN for moves.
        delete_old_rdn: Whether to delete the old RDN value.

    Returns:
        Parameter mapping for the ldap3 modify_dn call.

    Raises:
        ValueError: If the RDN is malformed.
    """
    if "=" not in new_rdn or "," in new_rdn:
        raise ValueError("new_rdn must be a single RDN (e.g. CN=Name)")
    return {"relative_dn": new_rdn, "new_superior": new_superior, "delete_old_rdn": delete_old_rdn}
