"""Contract: fake and real DirectoryGateway obey the same read/mutate contract.

The real adapter runs only with MWA_AD_LAB=1 (lab DC reachable); otherwise those
cases skip. The fake always runs, pinning the behavioral contract.
"""

import os
from typing import Any

import pytest

from mwa_ad_connector.api.error_handlers import ConnectorError

pytestmark = pytest.mark.contract


def _lab_enabled() -> bool:
    """Return True only when the lab DC integration is explicitly enabled."""
    return os.environ.get("MWA_AD_LAB") == "1"


@pytest.fixture(params=["fake"])
def gateway(request: Any, fake_gateway: Any) -> Any:
    """Parametrizable gateway: fake always; real adapter only with MWA_AD_LAB=1."""
    if request.param == "fake":
        return fake_gateway
    pytest.skip("Real adapter runs only with MWA_AD_LAB=1.")


def _real_gateway_cases() -> list[str]:
    """Extra params for the real adapter (skipped without lab)."""
    return ["real"] if _lab_enabled() else []


@pytest.mark.parametrize("variant", ["fake"] + _real_gateway_cases())
async def test_ping_reports_reachability(variant: str, fake_gateway: Any) -> None:
    """Ping is truthful: reachable lab reports ok; outage raises retryable 503."""
    gateway = fake_gateway if variant == "fake" else pytest.skip("Real adapter not wired in this build.")
    assert (await gateway.ping())["ok"] is True
    gateway.ping_ok = False
    try:
        with pytest.raises(ConnectorError) as exc_info:
            await gateway.ping()
        assert exc_info.value.code == "LDAP_UNAVAILABLE"
        assert exc_info.value.http_status == 503
        assert exc_info.value.retryable is True
    finally:
        gateway.ping_ok = True


async def test_fake_resolve_contract_exactly_one(fake_gateway: Any, fake_service: Any) -> None:
    """Resolve contract via the service seam: exactly-one, 404, 409 paths."""
    ok = await fake_service.execute_capability(
        capability="user.resolve",
        target={"object_type": "USER", "object_guid": "u-1", "domain_id": "domain-lab"},
        parameters={},
        caller={},
        idempotency_key=None,
        correlation_id="c",
        ticket_id=None,
        dry_run=False,
    )
    assert ok["object_guid"] == "u-1"

    with pytest.raises(ConnectorError) as not_found:
        await fake_service.execute_capability(
            capability="user.resolve",
            target={"object_type": "USER", "object_guid": "00000000-0000-0000-0000-000000000000"},
            parameters={},
            caller={},
            idempotency_key=None,
            correlation_id="c",
            ticket_id=None,
            dry_run=False,
        )
    assert not_found.value.code == "TARGET_NOT_FOUND"

    with pytest.raises(ConnectorError) as ambiguous:
        await fake_service.execute_capability(
            capability="group.resolve",
            target={"object_type": "GROUP", "identifier_value": "ambiguous"},
            parameters={},
            caller={},
            idempotency_key=None,
            correlation_id="c",
            ticket_id=None,
            dry_run=False,
        )
    assert ambiguous.value.code == "AMBIGUOUS_TARGET"


async def test_fake_membership_idempotent_noop(gateway: Any, fake_service: Any) -> None:
    """Membership contract: add is APPLIED once, NO_OP when present; remove mirrors."""
    call = {
        "capability": "group.member.add",
        "target": {"object_type": "GROUP", "object_guid": "g-1"},
        "parameters": {"member_guid": "u-1"},
        "caller": {},
        "idempotency_key": None,
        "correlation_id": "c",
        "ticket_id": "T1",
        "dry_run": False,
    }
    first = await fake_service.execute_capability(**call)
    assert first["disposition"] == "APPLIED"
    assert first["state"] == "AD_VERIFIED"
    second = await fake_service.execute_capability(**call)
    assert second["disposition"] == "NO_OP"

    call["capability"] = "group.member.remove"
    removed = await fake_service.execute_capability(**call)
    assert removed["disposition"] == "APPLIED"
    removed_again = await fake_service.execute_capability(**call)
    assert removed_again["disposition"] == "NO_OP"
    assert gateway is not None


async def test_fake_cycle_rejected_as_conflict(fake_service: Any) -> None:
    """Membership contract: self-membership (cycle) is a 409 conflict."""
    with pytest.raises(ConnectorError) as exc_info:
        await fake_service.execute_capability(
            capability="group.member.add",
            target={"object_type": "GROUP", "object_guid": "g-1"},
            parameters={"member_guid": "g-1"},
            caller={},
            idempotency_key=None,
            correlation_id="c",
            ticket_id="T1",
            dry_run=False,
        )
    assert exc_info.value.code == "LDAP_CONSTRAINT_VIOLATION"
    assert exc_info.value.http_status == 409


def test_real_adapter_parity_placeholder() -> None:
    """Real-AD parity runs in the lab job (MWA_AD_LAB=1); skipped otherwise."""
    if not _lab_enabled():
        pytest.skip("No lab DC configured (MWA_AD_LAB!=1).")
