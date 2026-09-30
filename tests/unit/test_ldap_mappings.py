"""Regression tests for LDAP entry -> domain model mapping (real ldap3 shapes).

Captured from a live DC via scripts/diag_entry.py:
- objectGUID arrives as a braced GUID string ({"{xxxxxxxx-...}"})
- pwdLastSet/whenChanged arrive as timezone-aware datetimes
- empty attributes arrive as empty lists (not missing keys)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from mwa_ad_connector.domain.objects import DirectoryUser
from mwa_ad_connector.infrastructure.ldap.mappings import _first, map_entry_to_user, parse_object_guid

GUID = uuid.UUID("ad3e3006-dc80-46ff-b258-e438ce494c11")
PWD_LAST_SET = datetime(2026, 9, 30, 7, 55, 29, 112871, tzinfo=UTC)


def _real_entry(**overrides: object) -> dict[str, object]:
    """Build an entry shaped like the live ldap3 response for jdoe."""
    attributes: dict[str, object] = {
        "objectGUID": f"{{{GUID}}}",
        "sAMAccountName": "jdoe",
        "userPrincipalName": "jdoe@corp.test.local",
        "displayName": [],
        "mail": [],
        "userAccountControl": 512,
        "lockoutTime": datetime(1601, 1, 1, tzinfo=UTC),  # ldap3 formats 0 as the AD epoch
        "pwdLastSet": PWD_LAST_SET,
        "whenChanged": datetime(2026, 9, 30, 7, 55, 29, tzinfo=UTC),
        "uSNChanged": 49231,
        "memberOf": [],
        "distinguishedName": "CN=jdoe,OU=Users,OU=Managed,DC=corp,DC=test,DC=local",
    }
    attributes.update(overrides)
    return {"dn": "CN=jdoe,OU=Users,OU=Managed,DC=corp,DC=test,DC=local", "attributes": attributes}


def _map(entry: dict[str, object]) -> DirectoryUser:
    """Map one raw entry with test boundaries."""
    return map_entry_to_user(entry, domain_id="domain-corp", source_dc="DC01", observed_at=datetime.now(UTC))


def test_object_guid_braced_string_form() -> None:
    user = _map(_real_entry())
    assert user.object_guid == GUID
    assert user.sam_account_name == "jdoe"
    assert user.user_principal_name == "jdoe@corp.test.local"
    assert user.enabled is True
    assert user.locked is False
    assert user.pwd_last_set == PWD_LAST_SET


def test_object_guid_bytes_and_braced_string_are_equal() -> None:
    braced = _map(_real_entry())
    raw = _map(_real_entry(objectGUID=[GUID.bytes_le]))
    assert braced.object_guid == raw.object_guid == GUID


def test_empty_list_attribute_values_map_to_none() -> None:
    user = _map(_real_entry())
    assert user.display_name is None
    assert user.member_of_guids == []


def test_lockout_time_derives_locked_state() -> None:
    assert _map(_real_entry()).locked is False
    assert _map(_real_entry(lockoutTime=datetime(2026, 9, 30, 9, 0, tzinfo=UTC))).locked is True
    assert _map(_real_entry(lockoutTime=133500000000000000)).locked is True
    assert _map(_real_entry(lockoutTime="0")).locked is False
    assert _map(_real_entry(lockoutTime=[datetime(2026, 9, 30, 9, 0, tzinfo=UTC)])).locked is True


def test_filetime_string_still_converted() -> None:
    user = _map(_real_entry(pwdLastSet="133500000000000000"))
    assert user.pwd_last_set is not None
    assert user.pwd_last_set.tzinfo is not None


def test_naive_pwd_datetime_is_normalized_to_utc() -> None:
    user = _map(_real_entry(pwdLastSet=datetime(2026, 9, 30, 7, 55, 29)))  # noqa: DTZ001 - naive input under test
    assert user.pwd_last_set is not None
    assert user.pwd_last_set.tzinfo == UTC


def test_first_empty_sequences_are_none() -> None:
    assert _first([]) is None
    assert _first(()) is None
    assert _first(["jdoe"]) == "jdoe"


def test_parse_object_guid_all_observed_forms() -> None:
    assert parse_object_guid(f"{{{GUID}}}") == GUID
    assert parse_object_guid(str(GUID)) == GUID
    assert parse_object_guid(GUID.bytes_le) == GUID
    assert parse_object_guid([GUID.bytes_le]) == GUID
    assert parse_object_guid(GUID.bytes_le.decode("latin1")) == GUID


def test_parse_object_guid_rejects_unknown_values() -> None:
    with pytest.raises(ValueError):
        parse_object_guid(None)
    with pytest.raises(ValueError):
        parse_object_guid("{not-a-guid}")
