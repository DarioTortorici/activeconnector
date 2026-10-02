"""Unit: mutation targets carrying only an identifier are resolved before planning.

S2 relaxes mutation identity: a mutation may reference its target by an
allowlisted identifier instead of ``object_guid``. The API service resolves the
identifier to a GUID before the mutation is planned, preserving the domain error
semantics (zero matches -> TARGET_NOT_FOUND, multiple -> AMBIGUOUS_TARGET).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mwa_ad_connector.domain.errors import AmbiguousTargetError, TargetNotFoundError
from tests.contract._composition_helpers import MANAGED_OU, caller, make_runtime
from tests.fakes.directory_gateway import FakeDirectoryGateway

pytestmark = pytest.mark.unit

UNLOCK_SCOPES = ["ad.account.unlock"]


def _identifier_target(value: str) -> dict[str, Any]:
    """Build a user target that carries only a resolvable identifier."""
    return {"object_type": "USER", "identifier_type": "SAM_ACCOUNT_NAME", "identifier_value": value}


async def _unlock(runtime: Any, target: dict[str, Any], key: str) -> dict[str, Any]:
    """Run an account.unlock mutation through the wired API service."""
    result: dict[str, Any] = await runtime.api_service.execute_capability(
        capability="account.unlock",
        target=target,
        parameters={"reason": "helpdesk"},
        caller=caller(UNLOCK_SCOPES),
        idempotency_key=key,
        correlation_id=f"corr-{key}",
        ticket_id="TICKET-IDENTIFIER",
        dry_run=False,
    )
    return result


async def test_identifier_target_is_resolved_then_applied(tmp_path: Path) -> None:
    """A single exact identifier match resolves to a GUID and the mutation applies."""
    gateway = FakeDirectoryGateway()
    guid = gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        result = await _unlock(runtime, _identifier_target("jdoe"), "idem-resolve-0001")
        assert result["state"] == "AD_VERIFIED"
        assert result["target_object_guid"] == str(guid)
    finally:
        runtime.close()


async def test_zero_match_identifier_raises_target_not_found(tmp_path: Path) -> None:
    """An identifier with no exact match fails with the domain not-found error."""
    gateway = FakeDirectoryGateway()
    runtime = make_runtime(tmp_path, gateway)
    try:
        with pytest.raises(TargetNotFoundError):
            await _unlock(runtime, _identifier_target("ghost"), "idem-resolve-0002")
    finally:
        runtime.close()


async def test_multiple_match_identifier_raises_ambiguous_target(tmp_path: Path) -> None:
    """An identifier with more than one exact match fails as ambiguous."""
    gateway = FakeDirectoryGateway()
    gateway.seed_user(sam="jdoe", dn=f"CN=jdoe,{MANAGED_OU}")
    gateway.seed_user(sam="jdoe", dn=f"CN=jdoe2,{MANAGED_OU}")
    runtime = make_runtime(tmp_path, gateway)
    try:
        with pytest.raises(AmbiguousTargetError):
            await _unlock(runtime, _identifier_target("jdoe"), "idem-resolve-0003")
    finally:
        runtime.close()
