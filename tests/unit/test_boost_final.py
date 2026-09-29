"""Coverage boost final: audit service, group delete, LDAP discovery with fake manager."""

from __future__ import annotations

import uuid
from typing import Any, cast

import pytest

from mwa_ad_connector.application.services.group_service import GroupNotEmptyError, GroupService
from mwa_ad_connector.domain.errors import TargetNotFoundError
from mwa_ad_connector.infrastructure.ldap.discovery import DomainCapabilities, RootDse, get_capabilities, get_rootdse
from mwa_ad_connector.operations.audit import AuditService, AuditStage
from tests.fakes.directory_gateway import FakeDirectoryGateway


class _MemSink:
    def __init__(self) -> None:
        self.entries: list[Any] = []

    async def append(self, entry: Any) -> str:
        self.entries.append(entry)
        return f"entry-{len(self.entries)}"


async def test_audit_service_redacts_and_logs_all_stages() -> None:
    sink = _MemSink()
    svc = AuditService(sink)
    entry_id = await svc.record(
        AuditStage.COMMIT,
        operation_id="op-1",
        capability="account.unlock",
        tenant_id="t",
        connector_id="c",
        caller_subject="caller",
        target_dn="CN=Jane Doe,OU=Users,DC=lab,DC=local",
        details={"new_password": "must-not-leak", "dry_run": False},  # noqa: S105 - test-only canary.
    )
    assert entry_id == "entry-1"
    entry = sink.entries[0]
    assert entry.target_dn == "CN=***,OU=***,DC=lab,DC=local"
    assert entry.details["new_password"] == "***REDACTED***"  # noqa: S105 - redaction placeholder.
    assert entry.details["dry_run"] is False
    assert await svc.log_requested(operation_id="op-1") == "entry-2"
    assert await svc.log_before(operation_id="op-1") == "entry-3"
    assert await svc.log_after(operation_id="op-1") == "entry-4"
    assert await svc.log_commit(operation_id="op-1") == "entry-5"
    assert await svc.log_verify(operation_id="op-1") == "entry-6"
    assert [e.stage for e in sink.entries] == [
        AuditStage.COMMIT,
        AuditStage.REQUESTED,
        AuditStage.BEFORE,
        AuditStage.AFTER,
        AuditStage.COMMIT,
        AuditStage.VERIFY,
    ]


async def test_group_delete_guards() -> None:
    gw = FakeDirectoryGateway()
    svc = GroupService(gw)
    empty_guid = gw.seed_group(name="empty-grp")
    deleted = await svc.delete(empty_guid)
    assert deleted.disposition == "APPLIED"
    with pytest.raises(TargetNotFoundError):
        await svc.delete(empty_guid)
    full_guid = gw.seed_group(name="full-grp")
    member = gw.seed_user(sam="member1")
    await gw.add_group_member(full_guid, member)
    with pytest.raises(GroupNotEmptyError):
        await svc.delete(full_guid)
    with pytest.raises(TargetNotFoundError):
        await svc.delete(uuid.uuid4())


class _FakeLdapEntry:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.entry_attributes_as_dict = attrs


class _FakeLdapConn:
    def __init__(self, result_code: int = 0, attrs: dict[str, Any] | None = None) -> None:
        self.result = {"result": result_code, "description": "ok" if result_code == 0 else "fail"}
        self.entries = [_FakeLdapEntry(attrs)] if attrs is not None else []
        self.searched = False

    def search(self, *args: Any, **kwargs: Any) -> bool:
        _ = (args, kwargs)
        self.searched = True
        return True


class _FakeManager:
    def __init__(self, conn: _FakeLdapConn, ldaps: bool = True) -> None:
        self._conn = conn
        self.pinned_host = "dc-lab.local"
        self.is_ldaps_enforced = ldaps

    async def execute(self, op: Any, pinned_dc: Any = None) -> tuple[Any, str]:
        _ = pinned_dc
        return op(self._conn), "dc-lab.local"


_ROOT_ATTRS: dict[str, Any] = {
    "namingContexts": ["DC=lab,DC=local"],
    "defaultNamingContext": ["DC=lab,DC=local"],
    "dnsHostName": ["dc-lab.local"],
    "forestFunctionality": ["7"],
    "domainFunctionality": ["7"],
    "supportedControl": ["1.2.840.113556.1.4.319"],
    "supportedCapabilities": ["1.2.840.113556.1.4.800"],
}


async def test_ldap_discovery_rootdse_ok() -> None:
    root = await get_rootdse(cast(Any, _FakeManager(_FakeLdapConn(0, dict(_ROOT_ATTRS)))))
    assert isinstance(root, RootDse)
    assert root.naming_contexts == ["DC=lab,DC=local"]
    assert root.default_naming_context == "DC=lab,DC=local"
    assert root.source_dc == "dc-lab.local"


async def test_ldap_discovery_rootdse_failure_and_empty() -> None:
    with pytest.raises(RuntimeError, match="TARGET_NOT_FOUND"):
        await get_rootdse(cast(Any, _FakeManager(_FakeLdapConn(32, dict(_ROOT_ATTRS)))))
    empty = await get_rootdse(cast(Any, _FakeManager(_FakeLdapConn(0, None))))
    assert empty.naming_contexts == []


async def test_ldap_discovery_capabilities() -> None:
    full = await get_capabilities(cast(Any, _FakeManager(_FakeLdapConn(0, dict(_ROOT_ATTRS)))), "domain-lab")
    assert isinstance(full, DomainCapabilities)
    assert full.paging_supported is True
    assert full.missing == []
    bare = await get_capabilities(cast(Any, _FakeManager(_FakeLdapConn(0, {}), ldaps=False)), "domain-lab")
    assert set(bare.missing) == {"paging", "ldaps", "functional-level"}
