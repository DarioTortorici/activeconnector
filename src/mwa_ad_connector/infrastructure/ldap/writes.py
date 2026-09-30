"""Write side of the LDAP adapter (membership / account / lifecycle)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import SecretStr

from mwa_ad_connector.application.ports.directory_gateway import AttributeMap
from mwa_ad_connector.infrastructure.ldap.common import (
    _GROUP_ALLOWLIST,
    _GUID_ATTRS,
    _USER_ALLOWLIST,
    _check,
)
from mwa_ad_connector.infrastructure.ldap.core import LdapAdapterCore
from mwa_ad_connector.infrastructure.ldap.filters import validate_dn_syntax
from mwa_ad_connector.infrastructure.ldap.mutations import (
    build_modify_dn,
    encode_unicode_pwd,
    staged_modify,
    uac_bit_safe,
)


def _add_values(value: Any) -> list[Any]:  # noqa: ANN401 - attribute values are heterogeneous.
    """Normalize an attribute value for ``conn.add`` (scalars become one-item lists)."""
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


class LdapAdapterWrites(LdapAdapterCore):
    """GUID-keyed mutations; DNs are refreshed immediately before each write."""

    async def add_group_member(self, group_guid: UUID, member_guid: UUID) -> None:
        """Add a member (DNs refreshed from GUIDs immediately before write)."""
        from ldap3 import MODIFY_ADD  # noqa: PLC0415

        group_dn = await self._dn_for_guid(group_guid, _GUID_ATTRS)
        member_dn = await self._dn_for_guid(member_guid, _GUID_ATTRS)
        await self._modify_raw(group_dn, {"member": [(MODIFY_ADD, [member_dn])]}, "add-member")

    async def remove_group_member(self, group_guid: UUID, member_guid: UUID) -> None:
        """Remove a member (DNs refreshed from GUIDs immediately before write)."""
        from ldap3 import MODIFY_DELETE  # noqa: PLC0415

        group_dn = await self._dn_for_guid(group_guid, _GUID_ATTRS)
        member_dn = await self._dn_for_guid(member_guid, _GUID_ATTRS)
        await self._modify_raw(group_dn, {"member": [(MODIFY_DELETE, [member_dn])]}, "remove-member")

    async def unlock_account(self, user_guid: UUID) -> None:
        """Clear lockoutTime (unlock)."""
        from ldap3 import MODIFY_REPLACE  # noqa: PLC0415

        user_dn = await self._dn_for_guid(user_guid, _GUID_ATTRS)
        await self._modify_raw(user_dn, {"lockoutTime": [(MODIFY_REPLACE, [0])]}, "unlock")

    async def reset_password(self, user_guid: UUID, new_password: str) -> None:
        """Reset unicodePwd over LDAPS only (secret wrapped, never logged)."""
        from ldap3 import MODIFY_REPLACE  # noqa: PLC0415

        if not self.is_secure_transport:
            raise RuntimeError("LDAPS_CERTIFICATE_INVALID: password reset requires LDAPS")
        user_dn = await self._dn_for_guid(user_guid, _GUID_ATTRS)
        await self._modify_raw(
            user_dn,
            {"unicodePwd": [(MODIFY_REPLACE, [encode_unicode_pwd(SecretStr(new_password))])]},
            "reset-password",
        )

    async def set_pwd_last_set(self, user_guid: UUID, value: int) -> None:
        """Set pwdLastSet (0 forces change, -1 clears)."""
        from ldap3 import MODIFY_REPLACE  # noqa: PLC0415

        user_dn = await self._dn_for_guid(user_guid, _GUID_ATTRS)
        await self._modify_raw(user_dn, {"pwdLastSet": [(MODIFY_REPLACE, [value])]}, "pwd-last-set")

    async def set_account_enabled(self, user_guid: UUID, enabled: bool) -> None:
        """Bit-safe userAccountControl enable/disable."""
        from ldap3 import MODIFY_REPLACE  # noqa: PLC0415

        user_dn = await self._dn_for_guid(user_guid, _GUID_ATTRS)
        current = await self._read_uac(user_dn)
        await self._modify_raw(
            user_dn, {"userAccountControl": [(MODIFY_REPLACE, [uac_bit_safe(current, enabled)])]}, "account-enabled"
        )

    async def _read_uac(self, user_dn: str) -> int:
        entry = await self._lookup_raw(user_dn, ["userAccountControl"])
        if entry is None:
            return 0
        attrs = entry.get("attributes")
        if not isinstance(attrs, dict):
            return 0
        raw = attrs.get("userAccountControl", [0])
        first = raw[0] if isinstance(raw, list) and raw else raw
        try:
            return int(str(first))
        except (TypeError, ValueError):
            return 0

    async def update_user_attributes(self, user_guid: UUID, attributes: AttributeMap) -> None:
        """Write allowlisted user attributes via minimal staged diff."""
        user_dn = await self._dn_for_guid(user_guid, _GUID_ATTRS)
        old = await self._read_current(user_dn, list(_USER_ALLOWLIST) + ["objectGUID"])
        desired = {k: ([v] if isinstance(v, str) else [str(i) for i in v]) for k, v in attributes.items()}
        staged = staged_modify(old, desired, _USER_ALLOWLIST)
        if staged:
            await self._modify_raw(user_dn, self._to_changes(staged), "update-user-attrs")

    async def update_group_attributes(self, group_guid: UUID, attributes: AttributeMap) -> None:
        """Write allowlisted group attributes via minimal staged diff."""
        group_dn = await self._dn_for_guid(group_guid, _GUID_ATTRS)
        old = await self._read_current(group_dn, list(_GROUP_ALLOWLIST) + ["objectGUID"])
        desired = {k: ([v] if isinstance(v, str) else [str(i) for i in v]) for k, v in attributes.items()}
        staged = staged_modify(old, desired, _GROUP_ALLOWLIST)
        if staged:
            await self._modify_raw(group_dn, self._to_changes(staged), "update-group-attrs")

    async def _read_current(self, dn: str, attributes: list[str]) -> dict[str, list[str]]:
        entry = await self._lookup_raw(dn, attributes)
        old: dict[str, list[str]] = {}
        if entry is not None:
            attrs = entry.get("attributes")
            if isinstance(attrs, dict):
                for key, val in attrs.items():
                    items = val if isinstance(val, list) else [val]
                    old[key] = [str(v) for v in items]
        return old

    @staticmethod
    def _to_changes(staged: list[tuple[str, str, list[str]]]) -> dict[str, list[tuple[str, list[Any]]]]:
        from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE  # noqa: PLC0415

        op_map = {"ADD": MODIFY_ADD, "DELETE": MODIFY_DELETE, "REPLACE": MODIFY_REPLACE}
        return {attr: [(op_map[op], list(values))] for attr, op, values in staged}

    async def create_user(self, parent_dn: str, attributes: AttributeMap) -> UUID:
        """Create a user under a managed OU and return its GUID."""
        for name in attributes:
            lowered = name.lower()
            if lowered not in _USER_ALLOWLIST and lowered not in (
                "samaccountname",
                "userprincipalname",
                "cn",
                "objectclass",
            ):
                raise ValueError(f"REQUEST_INVALID: attribute not allowlisted: {name}")
        sam = attributes.get("sAMAccountName", attributes.get("cn", "newuser"))
        sam_str = sam[0] if isinstance(sam, list) and sam else str(sam)
        dn = f"CN={sam_str},{validate_dn_syntax(parent_dn)}"

        def _op(conn: Any) -> None:
            ldap_attrs = {k: _add_values(v) for k, v in attributes.items()}
            conn.add(dn, ["top", "person", "organizationalPerson", "user"], ldap_attrs)
            _check(conn, "add")

        await self._manager.execute(_op)
        guid = await self._guid_for_dn(dn, _GUID_ATTRS)
        if guid is None:
            raise RuntimeError("AD_COMMITTED_VERIFICATION_FAILED: created user not readable")
        return guid

    async def create_group(self, parent_dn: str, attributes: AttributeMap) -> UUID:
        """Create a group under a managed OU and return its GUID."""
        for name in attributes:
            if name.lower() not in _GROUP_ALLOWLIST and name.lower() not in (
                "samaccountname",
                "name",
                "cn",
                "objectclass",
                "grouptype",
            ):
                raise ValueError(f"REQUEST_INVALID: attribute not allowlisted: {name}")
        name_value = attributes.get("name", attributes.get("sAMAccountName", "newgroup"))
        group_name = name_value[0] if isinstance(name_value, list) and name_value else str(name_value)
        dn = f"CN={group_name},{validate_dn_syntax(parent_dn)}"

        def _op(conn: Any) -> None:
            ldap_attrs = {k: _add_values(v) for k, v in attributes.items()}
            conn.add(dn, ["top", "group"], ldap_attrs)
            _check(conn, "add-group")

        await self._manager.execute(_op)
        guid = await self._guid_for_dn(dn, _GUID_ATTRS)
        if guid is None:
            raise RuntimeError("AD_COMMITTED_VERIFICATION_FAILED: created group not readable")
        return guid

    async def create_ou(self, parent_dn: str, name: str) -> UUID:
        """Create a child OU and return its GUID."""
        dn = f"OU={name},{validate_dn_syntax(parent_dn)}"

        def _op(conn: Any) -> None:
            conn.add(dn, ["top", "organizationalUnit"], {"ou": [name]})
            _check(conn, "add-ou")

        await self._manager.execute(_op)
        guid = await self._guid_for_dn(dn, _GUID_ATTRS)
        if guid is None:
            raise RuntimeError("AD_COMMITTED_VERIFICATION_FAILED: created OU not readable")
        return guid

    async def rename_entry(self, guid: UUID, new_rdn: str) -> str:
        """Rename an entry (GUID unchanged); returns the new DN."""
        params = build_modify_dn(new_rdn)
        dn = await self._dn_for_guid(guid, _GUID_ATTRS)

        def _op(conn: Any) -> None:
            conn.modify_dn(dn, str(params["relative_dn"]), delete_old_dn=bool(params["delete_old_rdn"]))
            _check(conn, "modify-dn")

        await self._manager.execute(_op)
        parent = ",".join(validate_dn_syntax(dn).split(",")[1:])
        return f"{new_rdn},{parent}"

    async def move_entry(self, guid: UUID, destination_dn: str) -> str:
        """Move an entry to a managed OU; returns the new DN."""
        superior = validate_dn_syntax(destination_dn)
        dn = await self._dn_for_guid(guid, _GUID_ATTRS)
        rdn = validate_dn_syntax(dn).split(",")[0]

        def _op(conn: Any) -> None:
            conn.modify_dn(dn, rdn, new_superior=superior, delete_old_dn=True)
            _check(conn, "modify-dn-move")

        await self._manager.execute(_op)
        return f"{rdn},{superior}"

    async def delete_entry(self, guid: UUID) -> None:
        """Delete a user or OU entry."""
        dn = await self._dn_for_guid(guid, _GUID_ATTRS)

        def _op(conn: Any) -> None:
            conn.delete(dn)
            _check(conn, "delete")

        await self._manager.execute(_op)

    async def delete_group(self, group_guid: UUID) -> None:
        """Delete a group by GUID."""
        await self.delete_entry(group_guid)

    async def delete_ou(self, guid: UUID) -> None:
        """Delete an OU by GUID (emptiness enforced by the OU service)."""
        await self.delete_entry(guid)
