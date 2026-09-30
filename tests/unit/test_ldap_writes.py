"""Regression: creates must normalize scalar attribute values for conn.add.

Real-AD failure: ``groupType`` is an int (-2147483646 for a global security
group); the old comprehension called ``list(int)`` -> TypeError -> HTTP 500.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, cast

import pytest

from mwa_ad_connector.infrastructure.ldap.connection import LdapConnectionManager
from mwa_ad_connector.infrastructure.ldap.writes import LdapAdapterWrites, _add_values


class FakeConn:
    """Connection stub capturing conn.add calls and returning empty searches."""

    def __init__(self) -> None:
        """Start with a success result and no entries."""
        self.result: dict[str, Any] = {"result": 0}
        self.entries: list[Any] = []
        self.added: list[tuple[str, list[str], dict[str, object]]] = []

    def add(self, dn: str, object_classes: list[str], attributes: dict[str, object]) -> None:
        """Capture one add call."""
        self.added.append((dn, object_classes, attributes))

    def search(
        self,
        base: str,
        search_filter: str,
        search_scope: object | None = None,
        attributes: list[str] | None = None,
    ) -> bool:
        """Return an empty result set (read-back happens in another call)."""
        del base, search_filter, search_scope, attributes
        return False


class FakeManager:
    """Executor wrapping the fake connection."""

    def __init__(self, connection: FakeConn) -> None:
        """Wrap the connection."""
        self.connection = connection

    async def execute(self, operation: Callable[[FakeConn], Any], pinned_dc: str | None = None) -> tuple[Any, str]:
        """Run the blocking operation."""
        del pinned_dc
        return operation(self.connection), "dc-fake"


def _adapter() -> tuple[LdapAdapterWrites, FakeConn]:
    conn = FakeConn()
    manager = cast("LdapConnectionManager", FakeManager(conn))
    adapter = LdapAdapterWrites(manager, base_dn="DC=lab", domain_id="domain-lab", forest_id="forest-lab")
    return adapter, conn


def test_add_values_normalizes_scalars_and_sequences() -> None:
    assert _add_values(-2147483646) == [-2147483646]
    assert _add_values("text") == ["text"]
    assert _add_values(["a", "b"]) == ["a", "b"]
    assert _add_values(("a",)) == ["a"]


def test_create_group_accepts_int_group_type() -> None:
    adapter, conn = _adapter()
    attributes: dict[str, Any] = {"name": "GRP-Test", "groupType": -2147483646, "description": "lab"}

    with pytest.raises(RuntimeError, match="created group not readable"):
        asyncio.run(adapter.create_group("OU=Groups,DC=lab", attributes))

    dn, object_classes, sent = conn.added[0]
    assert dn == "CN=GRP-Test,OU=Groups,DC=lab"
    assert object_classes == ["top", "group"]
    assert sent["groupType"] == [-2147483646]
    assert sent["name"] == ["GRP-Test"]
