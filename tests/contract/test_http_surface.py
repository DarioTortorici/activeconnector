"""HTTP surface contract: happy paths, paging round-trip, and status semantics."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import NOT_FOUND_GUID

pytestmark = pytest.mark.contract

USER_GUID = "91faf0e8-cfb6-49ea-80a7-e621986443f8"
GROUP_GUID = "7e565f72-8274-4cb8-b77a-7dad17a1b432"
OU_GUID = "a1111111-2222-3333-4444-555555555555"
APPROVAL = {"approval_id": "appr-1", "approved_by": ["boss"], "approved_at": "2026-01-15T09:59:00Z"}


def _mut(
    client: TestClient, headers: dict[str, str], method: str, path: str, body: dict[str, Any] | None = None
) -> Any:
    """Send a mutation with a fresh idempotency key per call (realistic client)."""
    fresh = dict(headers, **{"Idempotency-Key": uuid.uuid4().hex})
    if method == "DELETE":
        return client.request("DELETE", path, json=body or {}, headers=fresh)
    return client.post(path, json=body or {}, headers=fresh)


# --- discovery -------------------------------------------------------------


def test_rootdse_and_capabilities(client: TestClient, headers: dict[str, str]) -> None:
    """RootDSE + capabilities return redacted domain views."""
    rootdse = client.get("/api/v1/domains/domain-lab/rootdse", headers=headers)
    assert rootdse.status_code == 200
    assert rootdse.json()["domain_id"] == "domain-lab"
    caps = client.get("/api/v1/domains/domain-lab/capabilities", headers=headers)
    assert caps.status_code == 200
    assert "user.resolve" in caps.json()["capabilities"]


def test_resolve_user_and_group(client: TestClient, headers: dict[str, str]) -> None:
    """Resolve returns exactly-one redacted references."""
    user = client.post(
        "/api/v1/users:resolve",
        json={"object_type": "USER", "domain_id": "domain-lab", "object_guid": USER_GUID},
        headers=headers,
    )
    assert user.status_code == 200
    assert user.json()["object_guid"] == USER_GUID
    group = client.post(
        "/api/v1/groups:resolve",
        json={"object_type": "GROUP", "domain_id": "domain-lab", "object_guid": GROUP_GUID},
        headers=headers,
    )
    assert group.status_code == 200
    missing = client.post(
        "/api/v1/users:resolve",
        json={"object_type": "USER", "domain_id": "domain-lab", "object_guid": NOT_FOUND_GUID},
        headers=headers,
    )
    assert missing.status_code == 404


def test_get_user_and_group(client: TestClient, headers: dict[str, str]) -> None:
    """Typed get returns redacted objects with version tokens."""
    user = client.get(f"/api/v1/users/{USER_GUID}?projection=displayName,mail", headers=headers)
    assert user.status_code == 200
    assert user.json()["object_guid"] == USER_GUID
    group = client.get(f"/api/v1/groups/{GROUP_GUID}", headers=headers)
    assert group.status_code == 200


def test_search_paging_round_trip(client: TestClient, headers: dict[str, str]) -> None:
    """Search first page issues a signed token; second page terminates."""
    first = client.post(
        "/api/v1/users:search",
        json={
            "domain_id": "domain-lab",
            "object_type": "USER",
            "query_profile": "by-name",
            "parameters": {"name": "test"},
        },
        headers=headers,
    )
    assert first.status_code == 200
    token = first.json()["next_page_token"]
    assert token, "First page must carry a continuation token."
    second = client.post(
        "/api/v1/users:search",
        json={"domain_id": "domain-lab", "object_type": "USER", "query_profile": "by-name", "page_token": token},
        headers=headers,
    )
    assert second.status_code == 200
    assert second.json()["next_page_token"] is None


def test_list_members(client: TestClient, headers: dict[str, str]) -> None:
    """Members list returns paged members with unresolved accounting."""
    response = client.get(f"/api/v1/groups/{GROUP_GUID}/members", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["group_guid"] == GROUP_GUID
    assert body["unresolved_count"] == 0


# --- accounts --------------------------------------------------------------


def test_unlock_verified_and_noop(client: TestClient, headers: dict[str, str]) -> None:
    """Unlock returns 200 AD_VERIFIED/APPLIED; already-unlocked is NO_OP."""
    applied = _mut(client, headers, "POST", f"/api/v1/users/{USER_GUID}:unlock", {"reason": "ticket"})
    assert applied.status_code == 200
    assert applied.json()["state"] == "AD_VERIFIED"
    noop = _mut(client, headers, "POST", "/api/v1/users/x-noop:unlock", {"reason": "ticket"})
    assert noop.json()["disposition"] == "NO_OP"


def test_password_reset_and_force_change(client: TestClient, headers: dict[str, str]) -> None:
    """Password reset/force-change verify without echoing secrets."""
    reset = _mut(
        client,
        headers,
        "POST",
        f"/api/v1/users/{USER_GUID}:reset-password",
        {"new_password": "Very-Long-Test-Password-1!", "force_change_at_logon": True},
    )
    assert reset.status_code == 200
    assert "Very-Long-Test-Password" not in reset.text
    force = _mut(client, headers, "POST", f"/api/v1/users/{USER_GUID}:force-password-change", {"force": True})
    assert force.status_code == 200


def test_enable_disable_update_rename_move(client: TestClient, headers: dict[str, str]) -> None:
    """Account state + attribute lifecycle endpoints verify synchronously."""
    assert _mut(client, headers, "POST", f"/api/v1/users/{USER_GUID}:enable", {}).status_code == 200
    disable = _mut(client, headers, "POST", f"/api/v1/users/{USER_GUID}:disable", {"reason": "leaver"})
    assert disable.status_code == 200
    update = _mut(
        client,
        headers,
        "POST",
        f"/api/v1/users/{USER_GUID}:update-attributes",
        {"attributes": {"displayName": "New Name", "department": "IT"}},
    )
    assert update.status_code == 200
    assert _mut(client, headers, "POST", f"/api/v1/users/{USER_GUID}:rename", {"new_rdn": "CN=New"}).status_code == 200
    move = _mut(
        client,
        headers,
        "POST",
        f"/api/v1/users/{USER_GUID}:move",
        {"destination_ou": "OU=Groups,DC=lab,DC=example,DC=test"},
    )
    assert move.status_code == 200


def test_user_create_and_delete(client: TestClient, headers: dict[str, str]) -> None:
    """User create + approval-gated delete verify synchronously."""
    created = _mut(
        client,
        headers,
        "POST",
        "/api/v1/users",
        {"parent_ou": "OU=Users,DC=lab,DC=example,DC=test", "sam_account_name": "jdoe"},
    )
    assert created.status_code == 200
    deleted = _mut(client, headers, "DELETE", f"/api/v1/users/{USER_GUID}", {"reason": "leaver", "approval": APPROVAL})
    assert deleted.status_code == 200


# --- groups ----------------------------------------------------------------


def test_group_membership_add_remove_idempotent(client: TestClient, headers: dict[str, str]) -> None:
    """Membership add/remove are idempotent (APPLIED then NO_OP)."""
    add = _mut(client, headers, "POST", f"/api/v1/groups/{GROUP_GUID}/members:add", {"member_guid": USER_GUID})
    assert add.json()["disposition"] == "APPLIED"
    add_again = _mut(client, headers, "POST", f"/api/v1/groups/{GROUP_GUID}/members:add", {"member_guid": USER_GUID})
    assert add_again.json()["disposition"] == "NO_OP"
    remove = _mut(client, headers, "POST", f"/api/v1/groups/{GROUP_GUID}/members:remove", {"member_guid": USER_GUID})
    assert remove.json()["disposition"] == "APPLIED"


def test_group_crud(client: TestClient, headers: dict[str, str]) -> None:
    """Group create/update/rename/move/delete verify synchronously."""
    assert (
        _mut(
            client,
            headers,
            "POST",
            "/api/v1/groups",
            {"parent_ou": "OU=Groups,DC=lab,DC=example,DC=test", "name": "grp-test", "scope": "GLOBAL"},
        ).status_code
        == 200
    )
    update = _mut(
        client, headers, "POST", f"/api/v1/groups/{GROUP_GUID}:update-attributes", {"attributes": {"description": "d"}}
    )
    assert update.status_code == 200
    assert (
        _mut(client, headers, "POST", f"/api/v1/groups/{GROUP_GUID}:rename", {"new_rdn": "CN=grp2"}).status_code == 200
    )
    move = _mut(
        client,
        headers,
        "POST",
        f"/api/v1/groups/{GROUP_GUID}:move",
        {"destination_ou": "OU=Groups,DC=lab,DC=example,DC=test"},
    )
    assert move.status_code == 200
    deleted = _mut(
        client, headers, "DELETE", f"/api/v1/groups/{GROUP_GUID}", {"reason": "cleanup", "approval": APPROVAL}
    )
    assert deleted.status_code == 200


# --- ous -------------------------------------------------------------------


def test_ou_crud(client: TestClient, headers: dict[str, str]) -> None:
    """OU create/rename/move/delete verify synchronously."""
    assert (
        _mut(
            client,
            headers,
            "POST",
            "/api/v1/ous",
            {"parent": "OU=Managed,DC=lab,DC=example,DC=test", "name": "Lifecycle"},
        ).status_code
        == 200
    )
    assert (
        _mut(client, headers, "POST", f"/api/v1/ous/{OU_GUID}:rename", {"new_rdn": "OU=Lifecycle2"}).status_code == 200
    )
    move = _mut(
        client,
        headers,
        "POST",
        f"/api/v1/ous/{OU_GUID}:move",
        {"destination_parent": "OU=Managed,DC=lab,DC=example,DC=test", "approval": APPROVAL},
    )
    assert move.status_code == 200
    deleted = _mut(client, headers, "DELETE", f"/api/v1/ous/{OU_GUID}", {"reason": "cleanup", "approval": APPROVAL})
    assert deleted.status_code == 200


# --- operations & audit ----------------------------------------------------


def test_operations_get_and_search(client: TestClient, headers: dict[str, str]) -> None:
    """Operation get/search return redacted records with paging."""
    got = client.get("/api/v1/operations/op-1", headers=headers)
    assert got.status_code == 200
    assert got.json()["operation_id"] == "op-1"
    searched = client.post(
        "/api/v1/operations:search", json={"filters": {"capability": "group.member.add"}}, headers=headers
    )
    assert searched.status_code == 200
    assert searched.json()["items"]


def test_audit_get_and_export(client: TestClient, headers: dict[str, str]) -> None:
    """Audit get/export return redacted records and receipts."""
    got = client.get("/api/v1/audit/audit-1", headers=headers)
    assert got.status_code == 200
    exported = client.post(
        "/api/v1/audit:export",
        json={
            "requested_from": "2026-01-01T00:00:00Z",
            "requested_to": "2026-02-01T00:00:00Z",
            "approval_id": "appr-1",
        },
        headers=headers,
    )
    assert exported.status_code == 200
    assert exported.json()["export_id"] == "exp-1"
