"""Contract tests for the in-memory fake gateway (Step 2 deliverable)."""

from __future__ import annotations

from uuid import uuid4

from tests.fakes.directory_gateway import FAKE_DC_NAME, FakeDirectoryGateway


async def test_resolve_get_and_dc_pinning() -> None:
    """Seeded entries resolve with a fixed DC name for pinning assertions."""
    gateway = FakeDirectoryGateway()
    user_guid = gateway.seed_user()
    group_guid = gateway.seed_group()

    user_ref = await gateway.resolve_by_guid(user_guid)
    assert user_ref is not None
    assert user_ref.object_guid == user_guid

    user = await gateway.get_user(user_guid)
    assert user is not None
    assert user.source_dc == FAKE_DC_NAME == gateway.source_dc

    group = await gateway.get_group(group_guid)
    assert group is not None
    assert group.source_dc == FAKE_DC_NAME

    assert await gateway.resolve_by_guid(uuid4()) is None


async def test_membership_mutations_idempotent() -> None:
    """Add/remove membership is idempotent and observable."""
    gateway = FakeDirectoryGateway()
    user_guid = gateway.seed_user()
    group_guid = gateway.seed_group()

    await gateway.add_group_member(group_guid, user_guid)
    await gateway.add_group_member(group_guid, user_guid)
    assert await gateway.list_group_members(group_guid) == [user_guid]

    await gateway.remove_group_member(group_guid, user_guid)
    await gateway.remove_group_member(group_guid, user_guid)
    assert await gateway.list_group_members(group_guid) == []


async def test_account_and_search_behaviors() -> None:
    """Unlock, password reset marker, create/rename/move/delete and paging work."""
    gateway = FakeDirectoryGateway()
    user_guid = gateway.seed_user(sam="alice")
    gateway.seed_user(sam="alice2")

    await gateway.unlock_account(user_guid)
    await gateway.reset_password(user_guid, "Secret-123!")
    assert user_guid in gateway.password_resets

    await gateway.set_account_enabled(user_guid, False)
    disabled = await gateway.get_user(user_guid)
    assert disabled is not None and not disabled.enabled

    page1, token = await gateway.search_users("alice", page_size=1)
    assert len(page1) == 1
    assert token is not None
    page2, token2 = await gateway.search_users("alice", page_size=1, page_token=token)
    assert len(page2) == 1
    assert token2 is None

    new_dn = await gateway.rename_entry(user_guid, "CN=alice-renamed")
    assert new_dn.startswith("CN=alice-renamed")
    moved_dn = await gateway.move_entry(user_guid, "OU=Other,DC=lab,DC=local")
    assert moved_dn.endswith("OU=Other,DC=lab,DC=local")

    created = await gateway.create_user("OU=Users,DC=lab,DC=local", {"sAMAccountName": "bob"})
    assert await gateway.get_user(created) is not None
    await gateway.delete_entry(created)
    assert await gateway.get_user(created) is None

    group_guid = await gateway.create_group("OU=Groups,DC=lab,DC=local", {"name": "team"})
    assert await gateway.get_group(group_guid) is not None
    await gateway.update_group_attributes(group_guid, {"description": "redacted"})
    await gateway.delete_group(group_guid)
    assert await gateway.get_group(group_guid) is None

    ou_guid = await gateway.create_ou("DC=lab,DC=local", "Dept")
    assert await gateway.get_ou(ou_guid) is not None
    await gateway.delete_ou(ou_guid)

    rootdse = await gateway.get_rootdse("domain-lab")
    assert "namingContexts" in rootdse
