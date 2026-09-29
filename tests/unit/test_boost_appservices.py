"""Coverage boost: account/password/user/group/ou application services."""

from __future__ import annotations

import uuid
from uuid import UUID

import pytest
from pydantic import SecretStr

from mwa_ad_connector.application.services.account_service import AccountService
from mwa_ad_connector.application.services.group_service import GroupService
from mwa_ad_connector.application.services.ou_service import OuService
from mwa_ad_connector.application.services.password_service import InsecureChannelError, PasswordService
from mwa_ad_connector.application.services.user_service import UserService
from mwa_ad_connector.domain.errors import (
    ConcurrentModificationError,
    ProtectedTargetError,
    RequestInvalidError,
    TargetNotFoundError,
)
from tests.fakes.directory_gateway import FakeDirectoryGateway


def _protected(uid: UUID) -> tuple[bool, list[str]]:
    _ = uid
    return True, ["admins"]


async def test_account_unlock_and_noop() -> None:
    gw = FakeDirectoryGateway()
    guid = gw.seed_user(sam="carol")
    svc = AccountService(gw)
    noop = await svc.unlock(guid)
    assert noop.disposition == "NO_OP"
    gw._entries[guid].locked = True
    applied = await svc.unlock(guid)
    assert applied.disposition == "APPLIED"
    assert applied.changed_fields == ("lockoutTime",)
    with pytest.raises(TargetNotFoundError):
        await svc.unlock(uuid.uuid4())
    with pytest.raises(ProtectedTargetError):
        await AccountService(gw, is_protected=_protected).unlock(guid)


async def test_account_set_enabled() -> None:
    gw = FakeDirectoryGateway()
    guid = gw.seed_user(sam="dave")
    svc = AccountService(gw)
    noop = await svc.set_enabled(guid, True)
    assert noop.disposition == "NO_OP"
    applied = await svc.set_enabled(guid, False)
    assert applied.disposition == "APPLIED"
    user = await gw.get_user(guid)
    assert user is not None
    with pytest.raises(ConcurrentModificationError):
        await svc.set_enabled(guid, True, expected_version="stale-token")
    back = await svc.set_enabled(guid, True, expected_version=user.version_token)
    assert back.disposition == "APPLIED"
    with pytest.raises(TargetNotFoundError):
        await svc.set_enabled(uuid.uuid4(), True)


async def test_password_reset_and_force_change() -> None:
    gw = FakeDirectoryGateway()
    guid = gw.seed_user(sam="erin")
    svc = PasswordService(gw)
    outcome = await svc.reset(guid, SecretStr("N3w-secret-value!"))
    assert outcome.changed_fields == ("unicodePwd",)
    assert guid in gw.password_resets
    forced = await svc.force_change(guid, True)
    assert forced.changed_fields == ("pwdLastSet",)
    with pytest.raises(TargetNotFoundError):
        await svc.reset(uuid.uuid4(), SecretStr("x"))
    with pytest.raises(TargetNotFoundError):
        await svc.force_change(uuid.uuid4(), True)
    with pytest.raises(ProtectedTargetError):
        await PasswordService(gw, is_protected=_protected).reset(guid, SecretStr("x"))
    insecure_gw = FakeDirectoryGateway()
    insecure_gw.is_secure_transport = False  # type: ignore[attr-defined]
    insecure_guid = insecure_gw.seed_user(sam="fred")
    with pytest.raises(InsecureChannelError):
        await PasswordService(insecure_gw).reset(insecure_guid, SecretStr("x"))


async def test_user_lifecycle() -> None:
    gw = FakeDirectoryGateway()
    svc = UserService(gw)
    created = await svc.create("OU=Users,DC=lab,DC=local", {"sAMAccountName": "gina", "displayName": "Gina"})
    assert created.disposition == "APPLIED"
    guid = created.user_guid
    noop = await svc.update_attributes(guid, {"displayName": "Gina"})
    assert noop.disposition == "NO_OP"
    applied = await svc.update_attributes(guid, {"displayName": "Gina R."})
    assert applied.disposition == "APPLIED"
    with pytest.raises(RequestInvalidError):
        await svc.update_attributes(guid, {"nTSecurityDescriptor": "x"})
    with pytest.raises(ConcurrentModificationError):
        await svc.update_attributes(guid, {"displayName": "Z"}, expected_version="stale")
    renamed = await svc.rename(guid, "CN=Gina R.")
    assert renamed.changed_fields == ("rdn",)
    moved = await svc.move(guid, "OU=Sales,DC=lab,DC=local")
    assert moved.changed_fields == ("move",)
    with pytest.raises(TargetNotFoundError):
        await svc.update_attributes(uuid.uuid4(), {"displayName": "Z"})


async def test_group_lifecycle() -> None:
    gw = FakeDirectoryGateway()
    svc = GroupService(gw)
    created = await svc.create("OU=Groups,DC=lab,DC=local", {"name": "eng", "description": "Eng"})
    assert created.disposition == "APPLIED"
    assert created.group_guid is not None
    groups, _ = await gw.search_groups("eng", 10)
    assert len(groups) == 1
    target = groups[0].object_guid
    updated = await svc.update_attributes(target, {"description": "Engineering"})
    assert updated.disposition == "APPLIED"
    with pytest.raises(RequestInvalidError):
        await svc.update_attributes(target, {"nTSecurityDescriptor": "x"})
    renamed = await svc.rename(target, "CN=engineering")
    assert renamed.changed_fields == ("rdn",)
    moved = await svc.move(target, "OU=NewGroups,DC=lab,DC=local")
    assert moved.changed_fields == ("move",)
    with pytest.raises(TargetNotFoundError):
        await svc.rename(uuid.uuid4(), "CN=x")


async def test_ou_lifecycle() -> None:
    gw = FakeDirectoryGateway()
    svc = OuService(gw)
    created = await svc.create("DC=lab,DC=local", "Sales")
    assert created.disposition == "APPLIED"
    guid = created.ou_guid
    assert isinstance(guid, UUID)
    renamed = await svc.rename(guid, "OU=Marketing")
    assert renamed.changed_fields == ("rdn",)
    moved = await svc.move(guid, "DC=lab,DC=local")
    assert moved.changed_fields == ("move",)
    deleted = await svc.delete(guid)
    assert deleted.disposition == "APPLIED"
    with pytest.raises(TargetNotFoundError):
        await svc.delete(guid)
    with pytest.raises(TargetNotFoundError):
        await svc.rename(uuid.uuid4(), "CN=x")


async def test_user_delete() -> None:
    gw = FakeDirectoryGateway()
    svc = UserService(gw)
    created = await svc.create("OU=Users,DC=lab,DC=local", {"sAMAccountName": "hank"})
    deleted = await svc.delete(created.user_guid)
    assert deleted.disposition == "APPLIED"
    with pytest.raises(TargetNotFoundError):
        await svc.delete(created.user_guid)
