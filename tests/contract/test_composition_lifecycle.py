"""Contract: every lifecycle callback family executes and verifies over fakes."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from mwa_ad_connector.domain.errors import DomainError
from tests.contract._composition_helpers import MANAGED_OU, approval, caller, make_runtime
from tests.fakes.directory_gateway import FakeDirectoryGateway

pytestmark = pytest.mark.contract

ALL_SCOPES = [
    "ad.account.unlock",
    "ad.account.enable",
    "ad.account.disable",
    "ad.account.password.force_change",
    "ad.user.create",
    "ad.user.attributes.write",
    "ad.user.rename",
    "ad.user.move",
    "ad.user.delete",
    "ad.group.create",
    "ad.group.attributes.write",
    "ad.group.rename",
    "ad.group.move",
    "ad.group.delete",
    "ad.ou.create",
    "ad.ou.rename",
    "ad.ou.move",
    "ad.ou.delete",
]


async def _run(runtime: Any, capability: str, guid: str | None, parameters: dict[str, Any], key: str) -> dict[str, Any]:
    """Execute one mutation through the wired API service."""
    target: dict[str, Any] = {"object_guid": guid} if guid else {}
    result: dict[str, Any] = await runtime.api_service.execute_capability(
        capability=capability,
        target=target,
        parameters=parameters,
        caller=caller(ALL_SCOPES),
        idempotency_key=key,
        correlation_id=f"corr-{key}",
        ticket_id="TICKET-LIFECYCLE",
        dry_run=False,
    )
    return result


async def test_account_lifecycle_verified(tmp_path: Path) -> None:
    """Unlock (NO_OP when already unlocked), disable/enable and force-change verify."""
    gateway = FakeDirectoryGateway()
    guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        unlocked = await _run(runtime, "account.unlock", str(guid), {"reason": "helpdesk"}, "idem-unlock-0001")
        assert unlocked["state"] == "AD_VERIFIED"
        assert unlocked["disposition"] == "NO_OP"

        disabled = await _run(
            runtime,
            "account.disable",
            str(guid),
            {"reason": "leaver", "approval": approval()},
            "idem-disable-0001",
        )
        assert disabled["state"] == "AD_VERIFIED"
        user = await gateway.get_user(guid)
        assert user is not None and user.enabled is False

        enabled = await _run(
            runtime,
            "account.enable",
            str(guid),
            {"approval": approval()},
            "idem-enable-0001",
        )
        assert enabled["state"] == "AD_VERIFIED"
        assert enabled["disposition"] == "APPLIED"

        forced = await _run(
            runtime,
            "account.password.force_change",
            str(guid),
            {"force": True},
            "idem-force-change-0001",
        )
        assert forced["state"] == "AD_VERIFIED"
    finally:
        runtime.close()


async def test_user_lifecycle_verified(tmp_path: Path) -> None:
    """Create, update attributes, rename, move and delete a user end to end."""
    gateway = FakeDirectoryGateway()
    runtime = make_runtime(tmp_path, gateway)
    try:
        created = await _run(
            runtime,
            "user.create",
            None,
            {
                "parent_ou": MANAGED_OU,
                "sam_account_name": "newuser",
                "user_principal_name": "newuser@lab.local",
                "display_name": "New User",
            },
            "idem-user-create-1",
        )
        assert created["state"] == "AD_VERIFIED"
        guid = created["target_object_guid"]
        assert await gateway.get_user(UUID(guid)) is not None

        updated = await _run(
            runtime,
            "user.attributes.update",
            guid,
            {"attributes": {"displayName": "Renamed Display"}},
            "idem-user-update-1",
        )
        assert updated["state"] == "AD_VERIFIED"

        renamed = await _run(runtime, "user.rename", guid, {"new_rdn": "CN=newuser-renamed"}, "idem-user-rename")
        assert renamed["state"] == "AD_VERIFIED"
        assert renamed["resolved_dn_after"].startswith("CN=newuser-renamed")

        moved = await _run(runtime, "user.move", guid, {"destination_ou": MANAGED_OU}, "idem-user-move-1")
        assert moved["state"] == "AD_VERIFIED"

        deleted = await _run(
            runtime,
            "user.delete",
            guid,
            {"reason": "leaver", "approval": approval()},
            "idem-user-delete-1",
        )
        assert deleted["state"] == "AD_VERIFIED"
        assert await gateway.get_user(UUID(guid)) is None
    finally:
        runtime.close()


async def test_group_lifecycle_verified(tmp_path: Path) -> None:
    """Create, update, rename, move and delete a group end to end."""
    gateway = FakeDirectoryGateway()
    runtime = make_runtime(tmp_path, gateway)
    try:
        created = await _run(
            runtime,
            "group.create",
            None,
            {
                "parent_ou": MANAGED_OU,
                "name": "grp-lifecycle",
                "scope": "GLOBAL",
                "category": "SECURITY",
                "description": "lab",
            },
            "idem-group-create-1",
        )
        assert created["state"] == "AD_VERIFIED"
        guid = created["target_object_guid"]

        updated = await _run(
            runtime,
            "group.attributes.update",
            guid,
            {"attributes": {"description": "changed"}},
            "idem-group-update-1",
        )
        assert updated["state"] == "AD_VERIFIED"

        renamed = await _run(runtime, "group.rename", guid, {"new_rdn": "CN=grp-renamed"}, "idem-group-rename")
        assert renamed["state"] == "AD_VERIFIED"

        moved = await _run(runtime, "group.move", guid, {"destination_ou": MANAGED_OU}, "idem-group-move-1")
        assert moved["state"] == "AD_VERIFIED"

        deleted = await _run(
            runtime,
            "group.delete",
            guid,
            {"reason": "cleanup", "approval": approval()},
            "idem-group-delete-1",
        )
        assert deleted["state"] == "AD_VERIFIED"
    finally:
        runtime.close()


async def test_ou_lifecycle_verified(tmp_path: Path) -> None:
    """Create, rename, move and delete an OU end to end."""
    gateway = FakeDirectoryGateway()
    runtime = make_runtime(tmp_path, gateway)
    try:
        created = await _run(
            runtime,
            "ou.create",
            None,
            {"parent": MANAGED_OU, "name": "Lifecycle"},
            "idem-ou-create-1",
        )
        assert created["state"] == "AD_VERIFIED"
        guid = created["target_object_guid"]

        renamed = await _run(runtime, "ou.rename", guid, {"new_rdn": "OU=Lifecycle2"}, "idem-ou-rename-1")
        assert renamed["state"] == "AD_VERIFIED"

        moved = await _run(
            runtime,
            "ou.move",
            guid,
            {"destination_parent": MANAGED_OU, "approval": approval()},
            "idem-ou-move-1",
        )
        assert moved["state"] == "AD_VERIFIED"

        deleted = await _run(
            runtime,
            "ou.delete",
            guid,
            {"reason": "cleanup", "approval": approval()},
            "idem-ou-delete-1",
        )
        assert deleted["state"] == "AD_VERIFIED"
    finally:
        runtime.close()


async def test_move_destination_out_of_scope_denied(tmp_path: Path) -> None:
    """Move destinations outside the managed OUs are denied before any write."""
    gateway = FakeDirectoryGateway()
    guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        with pytest.raises(DomainError) as exc_info:
            await _run(
                runtime,
                "user.move",
                str(guid),
                {"destination_ou": "OU=Unmanaged,DC=lab,DC=local"},
                "idem-move-denied-1",
            )
        assert exc_info.value.code == "TARGET_OUT_OF_SCOPE"
    finally:
        runtime.close()
