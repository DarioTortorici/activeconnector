"""Coverage boost: services, operations, runtime helpers, persistence."""

from __future__ import annotations

import time
import uuid
from collections.abc import Collection
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from mwa_ad_connector.application.services.discovery_service import DiscoveryService
from mwa_ad_connector.application.services.group_membership_service import (
    GroupMembershipService,
    MembershipCycleError,
)
from mwa_ad_connector.application.services.identity_resolution_service import IdentityResolutionService
from mwa_ad_connector.application.verification.read_after_write import verify_with_same_dc
from mwa_ad_connector.domain.enums import IdentifierType, ObjectType
from mwa_ad_connector.domain.errors import RequestInvalidError, TargetNotFoundError
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.infrastructure.persistence.nonce_store import InMemoryNonceStore, SqliteNonceStore
from mwa_ad_connector.operations.idempotency import (
    IdempotencyClaim,
    IdempotencyCollision,
    canonical_request_hash,
    check,
    reserve,
)
from mwa_ad_connector.operations.retention import apply_retention, default_terminal_states
from mwa_ad_connector.operations.state_machine import InvalidTransition, advance, can_transition, is_terminal
from mwa_ad_connector.runtime.envelope import parse_approval, parse_bound
from mwa_ad_connector.runtime.params import (
    attributes_param,
    destination_dn,
    group_type_value,
    opt_str,
    required_str,
    uuid_param,
)
from tests.fakes.directory_gateway import FakeDirectoryGateway


class _MemRepo:
    def __init__(self) -> None:
        self.claims: dict[str, IdempotencyClaim] = {}

    async def claim_idempotency(
        self, *, tenant_id: str, connector_id: str, idempotency_key: str, request_hash: str, operation_id: str
    ) -> IdempotencyClaim:
        _ = (tenant_id, connector_id)
        existing = self.claims.get(idempotency_key)
        if existing is not None:
            return IdempotencyClaim(created=False, operation_id=existing.operation_id, stored_hash=existing.stored_hash)
        claim = IdempotencyClaim(created=True, operation_id=operation_id, stored_hash=request_hash)
        self.claims[idempotency_key] = claim
        return claim

    async def find_idempotency(
        self, *, tenant_id: str, connector_id: str, idempotency_key: str
    ) -> IdempotencyClaim | None:
        _ = (tenant_id, connector_id)
        return self.claims.get(idempotency_key)


def test_canonical_hash_stable_and_excludes() -> None:
    payload = {"b": 2, "a": 1, "nonce": "volatile"}
    assert canonical_request_hash(payload) != canonical_request_hash({"a": 1, "b": 2, "nonce": "other"})
    assert canonical_request_hash(payload, exclude=["nonce"]) == canonical_request_hash(
        {"a": 1, "b": 2}, exclude=["nonce"]
    )
    hashed = canonical_request_hash({"when": datetime(2024, 1, 1, tzinfo=UTC), "id": uuid.uuid4()})
    assert len(hashed) == 64


async def test_idempotency_reserve_and_check() -> None:
    repo = _MemRepo()
    claim = await reserve(
        repo, tenant_id="t", connector_id="c", idempotency_key="k1", request_hash="h1", operation_id="op-1"
    )
    assert claim.created is True
    same = await reserve(
        repo, tenant_id="t", connector_id="c", idempotency_key="k1", request_hash="h1", operation_id="op-1"
    )
    assert same.created is False
    with pytest.raises(IdempotencyCollision):
        await reserve(
            repo, tenant_id="t", connector_id="c", idempotency_key="k1", request_hash="other", operation_id="op-2"
        )
    found = await check(repo, tenant_id="t", connector_id="c", idempotency_key="k1", request_hash="h1")
    assert found is not None
    with pytest.raises(IdempotencyCollision):
        await check(repo, tenant_id="t", connector_id="c", idempotency_key="k1", request_hash="other")
    assert await check(repo, tenant_id="t", connector_id="c", idempotency_key="missing", request_hash="h") is None
    with pytest.raises(ValueError):
        await reserve(repo, tenant_id=" ", connector_id="c", idempotency_key="k", request_hash="h", operation_id="o")
    with pytest.raises(ValueError):
        await reserve(
            repo, tenant_id="t", connector_id="c", idempotency_key="x" * 200, request_hash="h", operation_id="o"
        )
    exc = IdempotencyCollision("op-9")
    assert exc.operation_id == "op-9"


def _ref(**kwargs: Any) -> ObjectReference:
    base: dict[str, Any] = {"domain_id": "domain-lab", "forest_id": "forest-lab"}
    base.update(kwargs)
    return ObjectReference(**base)


async def test_identity_resolution_guid_and_users() -> None:
    gw = FakeDirectoryGateway()
    user_guid = gw.seed_user(sam="alice")
    svc = IdentityResolutionService(gw)
    ref = _ref(object_type=ObjectType.USER, object_guid=user_guid)
    resolved = await svc.resolve(ref)
    assert resolved.object_guid == user_guid
    assert await svc.require_guid(ref) == user_guid
    assert (await svc.refresh(user_guid)).object_guid == user_guid
    with pytest.raises(TargetNotFoundError):
        await svc.resolve(_ref(object_type=ObjectType.USER, object_guid=uuid.uuid4()))
    with pytest.raises(TargetNotFoundError):
        await svc.refresh(uuid.uuid4())
    by_sam = _ref(
        object_type=ObjectType.USER, identifier_type=IdentifierType.SAM_ACCOUNT_NAME, identifier_value="alice"
    )
    assert (await svc.resolve(by_sam)).object_guid == user_guid
    gw._entries[user_guid].user_principal_name = "alice"
    by_upn = _ref(object_type=ObjectType.USER, identifier_type=IdentifierType.UPN, identifier_value="alice")
    assert (await svc.resolve(by_upn)).object_guid == user_guid
    with pytest.raises(TargetNotFoundError):
        await svc.resolve(
            _ref(object_type=ObjectType.USER, identifier_type=IdentifierType.SAM_ACCOUNT_NAME, identifier_value="ghost")
        )
    with pytest.raises(Exception):  # noqa: B017, PT011 - model validator rejects guid-less reference.
        await svc.resolve(_ref(object_type=ObjectType.USER))
    by_guid_str = _ref(
        object_type=ObjectType.USER, identifier_type=IdentifierType.OBJECT_GUID, identifier_value=str(user_guid)
    )
    assert (await svc.resolve(by_guid_str)).object_guid == user_guid


async def test_identity_resolution_groups_and_dn() -> None:
    gw = FakeDirectoryGateway()
    group_guid = gw.seed_group(name="devs")
    svc = IdentityResolutionService(gw)
    by_group = _ref(object_type=ObjectType.GROUP, identifier_type=IdentifierType.GROUP_NAME, identifier_value="devs")
    assert (await svc.resolve(by_group)).object_guid == group_guid
    with pytest.raises(TargetNotFoundError):
        await svc.resolve(
            _ref(object_type=ObjectType.GROUP, identifier_type=IdentifierType.GROUP_NAME, identifier_value="nogroup")
        )
    with pytest.raises(RequestInvalidError):
        await svc.resolve(
            _ref(object_type=ObjectType.USER, identifier_type=IdentifierType.DISTINGUISHED_NAME, identifier_value="x")
        )


async def test_discovery_service() -> None:
    gw = FakeDirectoryGateway()
    svc = DiscoveryService(gw)
    root = await svc.get_rootdse("domain-lab")
    assert root.naming_contexts == ["DC=lab,DC=local"]
    caps = await svc.get_capabilities("domain-lab")
    assert "paging" in caps.missing
    assert "functional-level" in caps.missing


async def test_group_membership_add_remove() -> None:
    gw = FakeDirectoryGateway()
    group_guid = gw.seed_group(name="team")
    user_guid = gw.seed_user(sam="bob")
    svc = GroupMembershipService(gw)
    first = await svc.add(group_guid, user_guid)
    assert first.disposition == "APPLIED"
    second = await svc.add(group_guid, user_guid)
    assert second.disposition == "NO_OP"
    removed = await svc.remove(group_guid, user_guid)
    assert removed.disposition == "APPLIED"
    removed_again = await svc.remove(group_guid, user_guid)
    assert removed_again.disposition == "NO_OP"
    with pytest.raises(MembershipCycleError):
        await svc.add(group_guid, group_guid)
    with pytest.raises(TargetNotFoundError):
        await svc.add(uuid.uuid4(), user_guid)
    with pytest.raises(TargetNotFoundError):
        await svc.remove(uuid.uuid4(), user_guid)


class _Reader:
    def __init__(self, observed: dict[str, Any] | None) -> None:
        self.observed = observed

    async def read_attributes(self, *, object_guid: str, dc: str | None = None) -> dict[str, Any] | None:
        _ = (object_guid, dc)
        return self.observed


async def test_verify_with_same_dc_matched_and_missing() -> None:
    ok = await verify_with_same_dc(
        reader=_Reader({"mail": ["a@b.c"]}),
        object_guid=str(uuid.uuid4()),
        dn="CN=x,DC=lab,DC=local",
        expected={"mail": ["a@b.c"]},
        dc="dc1",
    )
    assert ok.matched is True
    assert ok.redaction_applied is True
    missing = await verify_with_same_dc(
        reader=_Reader(None),
        object_guid=str(uuid.uuid4()),
        dn="CN=x,DC=lab,DC=local",
        expected={"mail": ["a@b.c"]},
        dc="dc1",
    )
    assert missing.matched is False


def test_parse_approval_and_bound() -> None:
    assert parse_approval({}) is None
    approval = parse_approval(
        {"approval": {"approval_id": "a1", "approved_by": ["boss"], "approved_at": "2024-01-01T00:00:00Z"}}
    )
    assert approval is not None and approval["approval_id"] == "a1"
    with pytest.raises(RequestInvalidError):
        parse_approval({"approval": "nope"})
    with pytest.raises(RequestInvalidError):
        parse_approval({"approval": {"approval_id": "", "approved_by": [], "approved_at": "nope"}})
    bound = parse_bound("2024-01-01T00:00:00Z", "since")
    assert bound.tzinfo is not None
    with pytest.raises(RequestInvalidError):
        parse_bound("not-a-date", "since")


def test_params_helpers() -> None:
    assert required_str({"k": "v"}, "k") == "v"
    with pytest.raises(RequestInvalidError):
        required_str({}, "k")
    assert opt_str(None) is None
    assert opt_str("") is None
    assert opt_str("x") == "x"
    guid = uuid.uuid4()
    assert uuid_param({"id": str(guid)}, "id") == guid
    with pytest.raises(RequestInvalidError):
        uuid_param({"id": "nope"}, "id")
    assert attributes_param({"attributes": {"mail": "a"}}) == {"mail": "a"}
    with pytest.raises(RequestInvalidError):
        attributes_param({"attributes": {}})
    assert destination_dn("ou.move", {"destination_parent": "OU=x,DC=l"}) == "OU=x,DC=l"
    assert destination_dn("user.move", {"destination_ou": "OU=y,DC=l"}) == "OU=y,DC=l"
    assert group_type_value("GLOBAL", "SECURITY") < 0
    assert group_type_value("GLOBAL", "DISTRIBUTION") > 0
    with pytest.raises(RequestInvalidError):
        group_type_value("NOPE", "SECURITY")
    with pytest.raises(RequestInvalidError):
        group_type_value("GLOBAL", "NOPE")


def test_state_machine_helpers() -> None:
    assert can_transition("RECEIVED", "AUTHORIZED") is True
    assert can_transition("RECEIVED", "ENTRA_CONVERGED") is False
    assert can_transition("NOPE", "AUTHORIZED") is False
    assert is_terminal("FAILED") is True
    assert is_terminal("RECEIVED") is False
    assert is_terminal("NOPE") is False
    assert advance("RECEIVED", "AUTHORIZED").value == "AUTHORIZED"
    with pytest.raises(InvalidTransition):
        advance("RECEIVED", "ENTRA_CONVERGED")


def test_default_terminal_states() -> None:
    assert "FAILED" in default_terminal_states()


class _PurgeStore:
    async def count_terminal_before(self, cutoff: datetime, *, terminal_states: Collection[str]) -> int:
        _ = (cutoff, terminal_states)
        return 3

    async def purge_terminal_before(self, cutoff: datetime, *, terminal_states: Collection[str]) -> int:
        _ = (cutoff, terminal_states)
        return 2


async def test_apply_retention() -> None:
    result = await apply_retention(_PurgeStore(), cutoff=datetime.now(UTC), dry_run=True)
    assert (result.checked, result.purged) == (3, 0)
    result2 = await apply_retention(_PurgeStore(), cutoff=datetime.now(UTC), dry_run=False)
    assert result2.purged == 2


def test_nonce_stores() -> None:
    mem = InMemoryNonceStore()
    assert mem.claim("n1", time.time() + 60) is True
    assert mem.claim("n1", time.time() + 60) is False
    assert mem.purge_expired(time.time() - 1) == 0
    sql = SqliteNonceStore()
    try:
        assert sql.claim("s1", time.time() + 60) is True
        assert sql.claim("s1", time.time() + 60) is False
        assert sql.purge_expired(time.time() - 1) == 0
    finally:
        sql.close()


def test_object_reference_guid_helper() -> None:
    guid: UUID = uuid.uuid4()
    ref = _ref(object_type=ObjectType.GROUP, object_guid=guid)
    assert ref.object_guid == guid
