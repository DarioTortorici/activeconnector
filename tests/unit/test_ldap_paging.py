"""Regression tests: cookie-paged search must consume ldap3 response dicts.

ldap3 ``paged_search(generator=True)`` yields raw response dicts
(``type``/``dn``/``attributes``), not ``Entry`` objects. The previous
implementation dropped every yielded item, so resolve/search always
returned zero results against a real DC.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

from ldap3.utils.ciDict import CaseInsensitiveDict

from mwa_ad_connector.infrastructure.ldap.connection import LdapConnectionManager
from mwa_ad_connector.infrastructure.ldap.core import LdapAdapterCore, _normalize_paged_entry, _paged_cookie
from mwa_ad_connector.infrastructure.ldap.mappings import map_entry_to_user

_PAGED_OID = "1.2.840.113556.1.4.319"


def _entry(index: int) -> dict[str, object]:
    """Build one ldap3-shaped searchResEntry response dict."""
    return {
        "type": "searchResEntry",
        "dn": f"CN=user{index},OU=Users,DC=lab",
        "attributes": {"sAMAccountName": [f"user{index}"]},
        "raw_attributes": {"sAMAccountName": [f"user{index}".encode()]},
    }


class FakeConnection:
    """Minimal cookie-paging ldap3 Connection stand-in."""

    def __init__(self, entries: list[dict[str, object]]) -> None:
        """Seed the fake result set."""
        self._all = list(entries)
        self.response: list[dict[str, object]] = []
        self.result: dict[str, Any] = {"result": 0}

    def search(
        self,
        base: str,
        search_filter: str,
        search_scope: object | None = None,
        attributes: list[str] | None = None,
        paged_size: int = 100,
        paged_cookie: bytes | None = None,
    ) -> None:
        """Serve one page keyed by the cookie-encoded offset."""
        del base, search_filter, search_scope, attributes
        start = int(paged_cookie.decode()) if paged_cookie else 0
        chunk = self._all[start : start + paged_size]
        self.response = chunk
        next_start = start + len(chunk)
        cookie = str(next_start).encode() if next_start < len(self._all) else b""
        self.result = {"result": 0, "controls": {_PAGED_OID: {"value": {"cookie": cookie}}}}


class FakeManager:
    """Callable executor around a fake connection."""

    def __init__(self, connection: FakeConnection) -> None:
        """Wrap the fake connection."""
        self.connection = connection

    async def execute(
        self, operation: Callable[[FakeConnection], Any], pinned_dc: str | None = None
    ) -> tuple[Any, str]:
        """Run the blocking operation against the fake connection."""
        del pinned_dc
        return operation(self.connection), "dc-fake"


def _core(entries: list[dict[str, object]]) -> LdapAdapterCore:
    """Build an adapter core bound to a fake connection."""
    manager = cast("LdapConnectionManager", FakeManager(FakeConnection(entries)))
    return LdapAdapterCore(manager, base_dn="DC=lab", domain_id="domain-lab", forest_id="forest-lab")


def test_normalize_paged_entry_prefers_decoded_attributes() -> None:
    assert _normalize_paged_entry(_entry(3)) == {
        "dn": "CN=user3,OU=Users,DC=lab",
        "attributes": {"sAMAccountName": ["user3"]},
    }


def test_normalize_accepts_case_insensitive_attribute_maps() -> None:
    """ldap3 attribute maps are CaseInsensitiveDict, not dict subclasses."""
    guid = uuid.uuid4()
    attrs: CaseInsensitiveDict = CaseInsensitiveDict()
    attrs["objectGUID"] = [guid.bytes_le]
    attrs["sAMAccountName"] = ["jdoe"]
    attrs["userAccountControl"] = [512]
    attrs["pwdLastSet"] = [0]
    attrs["whenChanged"] = ["20260930080000.0Z"]
    attrs["uSNChanged"] = [12345]
    item = {"type": "searchResEntry", "dn": "CN=jdoe,OU=Users,DC=lab", "attributes": attrs, "raw_attributes": attrs}

    normalized = _normalize_paged_entry(item)
    assert isinstance(normalized["attributes"], dict)

    mapped = map_entry_to_user(normalized, domain_id="domain-lab", source_dc="dc-fake", observed_at=datetime.now(UTC))
    assert mapped.sam_account_name == "jdoe"
    assert mapped.object_guid == guid


def test_paged_cookie_extracts_bytes_only() -> None:
    conn = FakeConnection([])
    conn.result = {"result": 0, "controls": {_PAGED_OID: {"value": {"cookie": b"abc"}}}}
    assert _paged_cookie(conn) == b"abc"
    conn.result = {"result": 0, "controls": {_PAGED_OID: {"value": {"cookie": b""}}}}
    assert _paged_cookie(conn) is None
    conn.result = {"result": 0}
    assert _paged_cookie(conn) is None


def test_paged_slices_without_loss_or_duplicates() -> None:
    core = _core([_entry(i) for i in range(5)])

    first, next_offset = asyncio.run(core._paged("(objectClass=user)", ["sAMAccountName"], 2, None))
    assert [e["dn"] for e in first] == ["CN=user0,OU=Users,DC=lab", "CN=user1,OU=Users,DC=lab"]
    assert next_offset == "2"

    second, next_offset2 = asyncio.run(core._paged("(objectClass=user)", ["sAMAccountName"], 2, next_offset))
    assert [e["dn"] for e in second] == ["CN=user2,OU=Users,DC=lab", "CN=user3,OU=Users,DC=lab"]
    assert next_offset2 == "4"

    third, next_offset3 = asyncio.run(core._paged("(objectClass=user)", ["sAMAccountName"], 2, next_offset2))
    assert [e["dn"] for e in third] == ["CN=user4,OU=Users,DC=lab"]
    assert next_offset3 is None

    collected = [str(e["dn"]) for page in (first, second, third) for e in page]
    assert collected == [f"CN=user{i},OU=Users,DC=lab" for i in range(5)]


def test_paged_offset_beyond_total_is_empty() -> None:
    core = _core([_entry(0)])
    page, token = asyncio.run(core._paged("(objectClass=user)", ["sAMAccountName"], 2, "10"))
    assert page == []
    assert token is None


def test_paged_empty_result_has_no_token() -> None:
    core = _core([])
    page, token = asyncio.run(core._paged("(objectClass=user)", ["sAMAccountName"], 2, None))
    assert page == []
    assert token is None
