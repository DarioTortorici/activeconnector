"""Coverage boost: LDAP pure helpers (filters, error mapping, mappings, common, controls)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from mwa_ad_connector.infrastructure.ldap import common as ldap_common
from mwa_ad_connector.infrastructure.ldap.controls import (
    PAGED_RESULTS_OID,
    PagedCookie,
    PagedSearchState,
    initial_cookie,
)
from mwa_ad_connector.infrastructure.ldap.error_mapping import extract_ad_subcode, map_ldap_result
from mwa_ad_connector.infrastructure.ldap.filters import (
    build_guid_filter,
    build_identifier_filter,
    build_query_profile_filter,
    escape_filter_value,
    list_query_profiles,
    reject_raw_filter,
    validate_dn_syntax,
)
from mwa_ad_connector.infrastructure.ldap.mappings import (
    build_version_token,
    filetime_to_datetime,
    group_type_to_scope_category,
    guid_bytes_le_to_uuid,
    map_entry_to_group,
    map_entry_to_ou,
    map_entry_to_user,
    redacted_attributes_view,
    sid_bytes_to_str,
    uac_to_enabled_locked,
)


def test_escape_filter_value() -> None:
    assert escape_filter_value("a*b(c)d\\e") == "a\\2ab\\28c\\29d\\5ce"
    assert escape_filter_value("a\x00b") == "a\\00b"
    with pytest.raises(ValueError):
        escape_filter_value("")
    with pytest.raises(ValueError):
        escape_filter_value("x" * 2000)


def test_reject_raw_filter_always() -> None:
    with pytest.raises(ValueError, match="forbidden"):
        reject_raw_filter("(cn=*)")


def test_build_guid_filter_roundtrip() -> None:
    guid = uuid.uuid4()
    filt = build_guid_filter(guid)
    assert filt.startswith("(objectGUID=")
    assert len(filt) > 20


def test_build_identifier_filter_allowlist() -> None:
    assert "userPrincipalName" in build_identifier_filter("UPN", "jdoe@lab.local")
    assert "sAMAccountName" in build_identifier_filter("SAM_ACCOUNT_NAME", "jdoe")
    assert "objectClass=group" in build_identifier_filter("GROUP_NAME", "grp*")
    assert build_identifier_filter("OBJECT_GUID", str(uuid.uuid4())).startswith("(objectGUID=")
    with pytest.raises(ValueError):
        build_identifier_filter("NOPE", "x")
    with pytest.raises(ValueError, match="base-object"):
        build_identifier_filter("DISTINGUISHED_NAME", "CN=x,DC=lab,DC=local")


def test_build_query_profile_filter() -> None:
    assert "userPrincipalName" in build_query_profile_filter("USER_BY_UPN", "j@lab.local")
    assert build_query_profile_filter("USER_BY_GUID", str(uuid.uuid4())).startswith("(objectGUID=")
    with pytest.raises(ValueError, match="unknown"):
        build_query_profile_filter("NOPE", "x")
    profiles = list_query_profiles()
    assert "USER_BY_UPN" in profiles


def test_validate_dn_syntax() -> None:
    assert validate_dn_syntax("CN=jdoe,OU=Users,DC=lab,DC=local") == "CN=jdoe,OU=Users,DC=lab,DC=local"
    with pytest.raises(ValueError):
        validate_dn_syntax("")
    with pytest.raises(ValueError):
        validate_dn_syntax("not a dn!!!")


def test_extract_ad_subcode() -> None:
    assert extract_ad_subcode(None) is None
    assert extract_ad_subcode("no code here") is None
    assert extract_ad_subcode("80090308: LdapErr: DSID-0C0906E8, data 52e, v4563") == "52e"


def test_map_ldap_result_codes() -> None:
    assert map_ldap_result(0).code == "OK"
    assert map_ldap_result(32).code == "TARGET_NOT_FOUND"
    assert map_ldap_result(49, "data 52e, xyz").code == "AUTHENTICATION_FAILED"
    assert map_ldap_result(49, "data 525, xyz").code == "TARGET_NOT_FOUND"
    assert map_ldap_result(49, "no subcode").code == "LDAP_INVALID_CREDENTIALS"
    assert map_ldap_result(999, operation="bind").code == "INTERNAL_ERROR"
    assert map_ldap_result(50, operation="unlock").remediation.startswith("Grant")
    assert map_ldap_result(52, operation="search").retryable is True
    assert map_ldap_result(82, operation="search").code == "LDAP_CONNECT_ERROR"


def test_guid_sid_filetime_uac() -> None:
    guid = uuid.uuid4()
    assert guid_bytes_le_to_uuid(guid.bytes_le) == guid
    with pytest.raises(ValueError):
        guid_bytes_le_to_uuid(b"short")
    with pytest.raises(ValueError):
        sid_bytes_to_str(b"short")
    with pytest.raises(ValueError):
        sid_bytes_to_str(b"\x01\x02\x00\x00\x00\x00\x00\x05" + b"\x00" * 4)
    assert filetime_to_datetime(0) is None
    assert filetime_to_datetime(0x7FFFFFFFFFFFFFFF) is None
    assert filetime_to_datetime(132000000000000000) is not None
    enabled, locked = uac_to_enabled_locked(0x0002)
    assert (enabled, locked) == (False, False)
    enabled2, locked2 = uac_to_enabled_locked(0x0010)
    assert (enabled2, locked2) == (True, True)


def test_group_type_and_version_token() -> None:
    scope, category = group_type_to_scope_category(0x80000002)
    assert (scope, category) == ("Global", "Security")
    scope2, category2 = group_type_to_scope_category(4)
    assert scope2 == "DomainLocal"
    assert category2 == "Distribution"
    token = build_version_token("2024-01-01", "123")
    assert len(token) == 32
    view = redacted_attributes_view({"cn": ["x"], "unicodePwd": ["secret"], "other": ["y"]}, frozenset({"cn", "other"}))
    assert view == {"cn": ["x"], "other": ["y"]}


def _user_entry(guid: uuid.UUID) -> dict[str, object]:
    return {
        "dn": "CN=jdoe,OU=Users,DC=lab,DC=local",
        "attributes": {
            "objectGUID": [guid.bytes_le],
            "sAMAccountName": ["jdoe"],
            "userPrincipalName": ["jdoe@lab.local"],
            "displayName": ["J Doe"],
            "userAccountControl": ["512"],
            "pwdLastSet": ["132000000000000000"],
            "whenChanged": ["20240101000000.0Z"],
            "uSNChanged": ["42"],
            "unicodePwd": ["must-not-leak"],
        },
    }


def test_map_entry_to_user_ok() -> None:
    guid = uuid.uuid4()
    user = map_entry_to_user(_user_entry(guid), domain_id="d1", source_dc="dc1", observed_at=datetime.now(UTC))
    assert user.object_guid == guid
    assert user.sam_account_name == "jdoe"
    assert "unicodePwd" not in user.attributes
    with pytest.raises(TypeError):
        map_entry_to_user(
            {"dn": "x", "attributes": "nope"}, domain_id="d", source_dc="s", observed_at=datetime.now(UTC)
        )
    with pytest.raises(ValueError):
        map_entry_to_user({"dn": "", "attributes": {}}, domain_id="d", source_dc="s", observed_at=datetime.now(UTC))


def test_map_entry_to_group_and_ou() -> None:
    guid = uuid.uuid4()
    group = map_entry_to_group(
        {
            "dn": "CN=grp,OU=Groups,DC=lab,DC=local",
            "attributes": {"objectGUID": [guid.bytes_le], "sAMAccountName": ["grp"], "name": ["grp"]},
        },
        domain_id="d1",
        source_dc="dc1",
        observed_at=datetime.now(UTC),
    )
    assert group.object_guid == guid
    ou = map_entry_to_ou(
        {
            "dn": "OU=Users,DC=lab,DC=local",
            "attributes": {"objectGUID": [guid.bytes_le], "ou": ["Users"]},
        },
        domain_id="d1",
        source_dc="dc1",
        observed_at=datetime.now(UTC),
    )
    assert ou.name == "Users"
    assert ou.parent_dn == "DC=lab,DC=local"
    with pytest.raises(ValueError):
        map_entry_to_group({"dn": "", "attributes": {}}, domain_id="d", source_dc="s", observed_at=datetime.now(UTC))


def test_ldap_common_helpers() -> None:
    class _Entry:
        entry_dn = "CN=x,DC=lab,DC=local"
        entry_attributes_as_dict = {"cn": ["x"]}

    as_dict = ldap_common._entry_to_dict(_Entry())
    assert as_dict["dn"] == "CN=x,DC=lab,DC=local"

    class _Conn:
        result = {"result": 0, "description": "ok"}

    ldap_common._check(_Conn(), "search")

    class _BadConn:
        result = {"result": 32, "description": "no such object"}

    with pytest.raises(RuntimeError, match="TARGET_NOT_FOUND"):
        ldap_common._check(_BadConn(), "search")
    assert ldap_common._now().tzinfo is not None


def test_paging_helpers() -> None:
    cookie = initial_cookie(page_size=10)
    assert cookie.page_size == 10
    assert PAGED_RESULTS_OID.startswith("1.2.840")
    with pytest.raises(ValueError):
        PagedCookie(cookie=b"", page_size=0)
    state = PagedSearchState()
    state.advance(b"next", ["CN=a,DC=lab,DC=local"])
    assert state.entries_seen == 1
    assert state.is_finished is False
    state.advance(b"", ["CN=b,DC=lab,DC=local"])
    assert state.is_finished is True
    with pytest.raises(ValueError, match="duplicate"):
        state.advance(b"", ["CN=A,DC=lab,DC=local"])
