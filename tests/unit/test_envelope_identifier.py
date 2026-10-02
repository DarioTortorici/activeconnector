"""Unit: canonical CommandEnvelope accepts identifier targets for mutations.

S2 relaxes the mutation identity requirement: a mutation may carry either the
stable ``object_guid`` or a resolvable identifier pair
(``identifier_type`` + ``identifier_value``). The runtime resolves the
identifier to a GUID before planning (Task 2); validation only checks that
*some* identity path is present.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from mwa_ad_connector.application.commands.envelope import CommandEnvelope


def _envelope(**overrides: Any) -> dict[str, Any]:
    """Build a minimal valid mutation envelope with a GUID target."""
    now = datetime.now(UTC)
    envelope: dict[str, Any] = {
        "schema_version": "1.0",
        "capability": "group.member.add",
        "customer_id": "customer-lab",
        "tenant_id": "tenant-lab",
        "connector_id": "connector-lab-01",
        "forest_id": "forest-lab",
        "domain_id": "domain-lab",
        "target": {
            "object_type": "GROUP",
            "object_guid": "7e565f72-8274-4cb8-b77a-7dad17a1b432",
            "domain_id": "domain-lab",
            "forest_id": "forest-lab",
        },
        "parameters": {"member": {"object_type": "USER", "object_guid": "91faf0e8-cfb6-49ea-80a7-e621986443f8"}},
        "idempotency_key": "idem-12345678",
        "correlation_id": "corr-12345678",
        "ticket_id": "TICKET-1",
        "requested_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "nonce": "nonce-12345678",
        "requested_by": "test-caller",
    }
    envelope.update(overrides)
    return envelope


def _identifier_target() -> dict[str, Any]:
    """A resolvable identifier target without object_guid."""
    return {
        "object_type": "GROUP",
        "identifier_type": "SAM_ACCOUNT_NAME",
        "identifier_value": "grp-lab",
        "domain_id": "domain-lab",
        "forest_id": "forest-lab",
    }


def test_mutation_with_identifier_only_is_valid() -> None:
    """A mutation target using only a resolvable identifier is accepted."""
    model = CommandEnvelope(**_envelope(target=_identifier_target()))
    assert model.target.has_stable_identity is False
    assert model.target.requires_resolution is True


def test_mutation_without_guid_or_identifier_is_rejected() -> None:
    """A mutation target with neither GUID nor identifier is rejected."""
    target = {"object_type": "GROUP", "domain_id": "domain-lab", "forest_id": "forest-lab"}
    with pytest.raises(ValidationError):
        CommandEnvelope(**_envelope(target=target))


def test_dry_run_mutation_without_guid_is_valid() -> None:
    """Dry-run mutations stay lenient: identifier target, no idempotency/ticket."""
    model = CommandEnvelope(
        **_envelope(
            dry_run=True,
            target=_identifier_target(),
            idempotency_key=None,
            ticket_id=None,
        )
    )
    assert model.dry_run is True
    assert model.target.requires_resolution is True


def test_non_mutation_envelope_with_identifier_is_valid() -> None:
    """Read capabilities (unchanged) accept an identifier target."""
    model = CommandEnvelope(
        **_envelope(
            capability="group.get",
            target=_identifier_target(),
            parameters={"projection": "summary"},
            idempotency_key=None,
            ticket_id=None,
        )
    )
    assert model.capability == "group.get"
    assert model.target.requires_resolution is True
