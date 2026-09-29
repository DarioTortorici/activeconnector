"""Contract: composition root wires gateway + stores + policy + services over fakes.

Every test runs without a real AD: the in-memory fake gateway and in-memory
SQLite stores exercise the same code paths the lab deployment uses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mwa_ad_connector.api import dependencies as deps
from mwa_ad_connector.api.app import create_app
from mwa_ad_connector.domain.errors import DomainError
from mwa_ad_connector.runtime.errors import coerce_infrastructure_fault, deny_to_error
from tests.conftest import TEST_CONNECTOR_ID, TEST_TENANT_ID, auth_headers, make_settings
from tests.contract._composition_helpers import (
    BIND_SECRET,
    JWT_SECRET,
    MANAGED_OU,
    MEMBER_SCOPES,
    PAGE_SECRET,
    RESET_SCOPES,
    RESET_SECRET,
    approval,
    caller,
    make_runtime,
)
from tests.fakes.directory_gateway import FakeDirectoryGateway

pytestmark = pytest.mark.contract


async def test_read_resolve_and_get(tmp_path: Path) -> None:
    """Reads return exact response shapes for resolve, typed get and members."""
    gateway = FakeDirectoryGateway()
    guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        resolved = await runtime.api_service.execute_capability(
            capability="user.resolve",
            target={"object_type": "USER", "object_guid": str(guid), "domain_id": "domain-lab"},
            parameters={},
            caller=caller(["ad.user.read"]),
            idempotency_key=None,
            correlation_id="corr-read-1",
            ticket_id=None,
            dry_run=False,
        )
        assert resolved["object_type"] == "USER"
        assert resolved["object_guid"] == str(guid)
        assert resolved["distinguished_name"]

        fetched = await runtime.api_service.execute_capability(
            capability="user.get",
            target={"object_type": "USER", "object_guid": str(guid)},
            parameters={"projection": ["sAMAccountName"]},
            caller=caller(["ad.user.read"]),
            idempotency_key=None,
            correlation_id="corr-read-2",
            ticket_id=None,
            dry_run=False,
        )
        assert fetched["object_type"] == "USER"
        assert fetched["domain_id"] == "domain-lab"
        assert set(fetched) == {
            "object_type",
            "object_guid",
            "distinguished_name",
            "domain_id",
            "display_name",
            "attributes",
            "version_token",
            "observed_at",
        }

        members = await runtime.api_service.execute_capability(
            capability="group.members.list",
            target={"object_type": "GROUP", "object_guid": str(guid)},
            parameters={"page_size": 10},
            caller=caller(["ad.group.members.read"]),
            idempotency_key=None,
            correlation_id="corr-read-3",
            ticket_id=None,
            dry_run=False,
        )
        assert set(members) == {"members", "unresolved_count", "next_cursor"}
    finally:
        runtime.close()


async def test_group_member_add_is_verified(tmp_path: Path) -> None:
    """A wired mutation executes through the orchestrator and verifies on the DC."""
    gateway = FakeDirectoryGateway()
    group_guid = gateway.seed_group(name="grp", dn=f"CN=grp,{MANAGED_OU}")
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        result = await runtime.api_service.execute_capability(
            capability="group.member.add",
            target={"object_type": "GROUP", "object_guid": str(group_guid)},
            parameters={"member_guid": str(user_guid)},
            caller=caller(MEMBER_SCOPES),
            idempotency_key="idem-member-add-1",
            correlation_id="corr-mut-1",
            ticket_id="TICKET-1",
            dry_run=False,
        )
        assert result["state"] == "AD_VERIFIED"
        assert result["disposition"] == "APPLIED"
        assert result["target_object_guid"] == str(group_guid)
        evidence = result["verification_evidence"]
        assert evidence["matched"] is True
        assert evidence["redaction_applied"] is True
        assert evidence["verification_type"] == "GROUP_MEMBERSHIP_PRESENT"
        assert user_guid in await gateway.list_group_members(group_guid)

        record = await runtime.api_service.get_operation(result["operation_id"], caller(MEMBER_SCOPES))
        assert record is not None
        assert record["state"] == "AD_VERIFIED"
        assert record["capability"] == "group.member.add"

        foreign = caller(MEMBER_SCOPES, tenant_id="tenant-evil")
        assert await runtime.api_service.get_operation(result["operation_id"], foreign) is None
    finally:
        runtime.close()


async def test_out_of_scope_target_denied(tmp_path: Path) -> None:
    """Targets outside the managed OUs are denied before any write."""
    gateway = FakeDirectoryGateway()
    group_guid = gateway.seed_group(name="grp", dn="CN=grp,OU=Unmanaged,DC=lab,DC=local")
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        with pytest.raises(DomainError) as exc_info:
            await runtime.api_service.execute_capability(
                capability="group.member.add",
                target={"object_type": "GROUP", "object_guid": str(group_guid)},
                parameters={"member_guid": str(user_guid)},
                caller=caller(MEMBER_SCOPES),
                idempotency_key="idem-out-of-scope",
                correlation_id="corr-deny-1",
                ticket_id="TICKET-1",
                dry_run=False,
            )
        assert exc_info.value.code == "TARGET_OUT_OF_SCOPE"
        assert await gateway.list_group_members(group_guid) == []
    finally:
        runtime.close()


async def test_protected_group_denied(tmp_path: Path) -> None:
    """Privileged groups are denied by protected-target policy."""
    gateway = FakeDirectoryGateway()
    group_guid = gateway.seed_group(name="Domain Admins", dn=f"CN=Domain Admins,{MANAGED_OU}")
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        with pytest.raises(DomainError) as exc_info:
            await runtime.api_service.execute_capability(
                capability="group.member.add",
                target={"object_type": "GROUP", "object_guid": str(group_guid)},
                parameters={"member_guid": str(user_guid)},
                caller=caller(MEMBER_SCOPES),
                idempotency_key="idem-protected",
                correlation_id="corr-deny-2",
                ticket_id="TICKET-1",
                dry_run=False,
            )
        assert exc_info.value.code == "PROTECTED_TARGET"
    finally:
        runtime.close()


async def test_missing_approval_denied(tmp_path: Path) -> None:
    """Approval-gated capabilities without approval context return APPROVAL_REQUIRED."""
    gateway = FakeDirectoryGateway()
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        with pytest.raises(DomainError) as exc_info:
            await runtime.api_service.execute_capability(
                capability="account.password.reset",
                target={"object_type": "USER", "object_guid": str(user_guid)},
                parameters={"new_password": RESET_SECRET, "force_change_at_logon": True},
                caller=caller(RESET_SCOPES),
                idempotency_key="idem-approval",
                correlation_id="corr-deny-3",
                ticket_id="TICKET-1",
                dry_run=False,
            )
        assert exc_info.value.code == "APPROVAL_REQUIRED"
        assert gateway.password_resets == []
    finally:
        runtime.close()


async def test_mutations_kill_switch_denied(tmp_path: Path) -> None:
    """enable_mutations=false denies every mutation before touching the gateway."""
    gateway = FakeDirectoryGateway()
    group_guid = gateway.seed_group(name="grp", dn=f"CN=grp,{MANAGED_OU}")
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway, enable_mutations=False)
    try:
        with pytest.raises(DomainError) as exc_info:
            await runtime.api_service.execute_capability(
                capability="group.member.add",
                target={"object_type": "GROUP", "object_guid": str(group_guid)},
                parameters={"member_guid": str(user_guid)},
                caller=caller(MEMBER_SCOPES),
                idempotency_key="idem-kill-switch",
                correlation_id="corr-deny-4",
                ticket_id="TICKET-1",
                dry_run=False,
            )
        assert exc_info.value.code == "CAPABILITY_NOT_ALLOWED"
        assert await gateway.list_group_members(group_guid) == []
    finally:
        runtime.close()


async def test_validation_mode_forces_dry_run(tmp_path: Path) -> None:
    """validation_mode_only=true turns mutations into preflight-only dry runs."""
    gateway = FakeDirectoryGateway()
    group_guid = gateway.seed_group(name="grp", dn=f"CN=grp,{MANAGED_OU}")
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway, validation_mode_only=True)
    try:
        result = await runtime.api_service.execute_capability(
            capability="group.member.add",
            target={"object_type": "GROUP", "object_guid": str(group_guid)},
            parameters={"member_guid": str(user_guid)},
            caller=caller(MEMBER_SCOPES),
            idempotency_key="idem-dry-run",
            correlation_id="corr-dry-1",
            ticket_id="TICKET-1",
            dry_run=False,
        )
        assert result["state"] == "AUTHORIZED"
        assert result["disposition"] == "NO_OP"
        assert await gateway.list_group_members(group_guid) == []
    finally:
        runtime.close()


async def test_no_secrets_in_results_records_or_readiness(tmp_path: Path) -> None:
    """Bind/JWT/page/reset secrets never reach results, records, audit or readiness."""
    gateway = FakeDirectoryGateway()
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    secrets = (BIND_SECRET, JWT_SECRET, PAGE_SECRET, RESET_SECRET)
    try:
        result = await runtime.api_service.execute_capability(
            capability="account.password.reset",
            target={"object_type": "USER", "object_guid": str(user_guid)},
            parameters={
                "new_password": RESET_SECRET,
                "force_change_at_logon": True,
                "approval": approval(),
            },
            caller=caller(RESET_SCOPES),
            idempotency_key="idem-password-reset-1",
            correlation_id="corr-secret-1",
            ticket_id="TICKET-1",
            dry_run=False,
        )
        assert result["state"] == "AD_VERIFIED"
        dumped_result = json.dumps(result)
        for secret in secrets:
            assert secret not in dumped_result

        record = await runtime.api_service.get_operation(result["operation_id"], caller(RESET_SCOPES))
        assert record is not None
        dumped_record = json.dumps(record, default=str)
        for secret in secrets:
            assert secret not in dumped_record

        entries = await runtime.audit_store.export(tenant_id=TEST_TENANT_ID, connector_id=TEST_CONNECTOR_ID)
        assert entries
        entry_key = str(entries[0]["_entry_key"])
        audit = await runtime.api_service.get_audit(entry_key, caller(["ad.audit.read"]))
        assert audit is not None
        dumped_audit = json.dumps(audit, default=str)
        for secret in secrets:
            assert secret not in dumped_audit

        readiness = await runtime.api_service.get_readiness()
        dumped_readiness = json.dumps(readiness)
        for secret in secrets:
            assert secret not in dumped_readiness
        assert "dc01.lab.local" not in dumped_readiness
        assert "DC=lab" not in dumped_readiness
        names = {check["name"] for check in readiness["checks"]}
        assert {
            "configuration_valid",
            "operation_store",
            "audit_store",
            "transport",
            "ldap_connectivity",
            "audit_chain",
        } <= names
        assert readiness["ready"] is True

        ping = await runtime.ping()
        assert ping["ok"] is True
        assert "dc01.lab.local" not in json.dumps(ping)

        dumped_settings = json.dumps(runtime.settings.model_dump_redacted(), default=str)
        for secret in secrets:
            assert secret not in dumped_settings
    finally:
        runtime.close()


def test_infrastructure_fault_mapping() -> None:
    """Adapter faults and policy denials map to stable domain error codes."""
    ldap_down = coerce_infrastructure_fault(RuntimeError("LDAP_UNAVAILABLE: dc down"))
    assert ldap_down.code == "LDAP_UNAVAILABLE"
    assert coerce_infrastructure_fault(ValueError("attribute not allowlisted: x")).code == "REQUEST_INVALID"
    assert coerce_infrastructure_fault(RuntimeError("boom")).code == "INTERNAL_ERROR"
    assert deny_to_error("PROTECTED_TARGET", "nope").code == "PROTECTED_TARGET"
    assert deny_to_error("APPROVAL_REQUIRED", "need approval").code == "APPROVAL_REQUIRED"
    assert deny_to_error("WEIRD_CODE", "fallback").code == "CAPABILITY_NOT_ALLOWED"


class _UnavailableGateway(FakeDirectoryGateway):
    """Fake gateway whose membership write fails with a mapped LDAP fault."""

    async def add_group_member(self, group_guid: Any, member_guid: Any) -> None:
        """Simulate a DC outage during the write."""
        raise RuntimeError("LDAP_UNAVAILABLE: dc down")


async def test_ldap_fault_maps_to_domain_error(tmp_path: Path) -> None:
    """A gateway RuntimeError surfaces as a mapped LDAP_UNAVAILABLE domain error."""
    gateway = _UnavailableGateway()
    group_guid = gateway.seed_group(name="grp", dn=f"CN=grp,{MANAGED_OU}")
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        with pytest.raises(DomainError) as exc_info:
            await runtime.api_service.execute_capability(
                capability="group.member.add",
                target={"object_type": "GROUP", "object_guid": str(group_guid)},
                parameters={"member_guid": str(user_guid)},
                caller=caller(MEMBER_SCOPES),
                idempotency_key="idem-ldap-down-1",
                correlation_id="corr-ldap-down",
                ticket_id="TICKET-1",
                dry_run=False,
            )
        assert exc_info.value.code == "LDAP_UNAVAILABLE"
    finally:
        runtime.close()


def test_create_app_boots_with_wired_ports(tmp_path: Path) -> None:
    """create_app(settings, gateway=..., operation_service=...) serves reads, mutations and mapped errors."""
    gateway = FakeDirectoryGateway()
    group_guid = gateway.seed_group(name="grp", dn=f"CN=grp,{MANAGED_OU}")
    user_guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    foreign_group = gateway.seed_group(name="other", dn="CN=other,OU=Unmanaged,DC=lab,DC=local")
    runtime = make_runtime(tmp_path, gateway)
    api_settings = make_settings()
    try:
        app = create_app(api_settings, gateway=runtime.gateway, operation_service=runtime.api_service)
        app.dependency_overrides[deps.get_settings] = lambda: api_settings
        client = TestClient(app, raise_server_exceptions=False)

        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["status"] == "HEALTHY"

        headers = auth_headers(api_settings)
        response = client.post(
            f"/api/v1/groups/{group_guid}/members:add",
            json={"member_guid": str(user_guid)},
            headers=headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "AD_VERIFIED"
        assert body["disposition"] == "APPLIED"
        for secret in (BIND_SECRET, JWT_SECRET, PAGE_SECRET, RESET_SECRET):
            assert secret not in response.text

        denied = client.post(
            f"/api/v1/groups/{foreign_group}/members:add",
            json={"member_guid": str(user_guid)},
            headers=dict(headers, **{"Idempotency-Key": "idem-http-denied"}),
        )
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "TARGET_OUT_OF_SCOPE"
    finally:
        runtime.close()
