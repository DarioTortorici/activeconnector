"""Unit: command-envelope validation (local worker model + canonical cross-check)."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from mwa_ad_connector.infrastructure.transport.worker import validate_envelope


def _valid_envelope(**overrides: object) -> dict[str, object]:
    """Build a minimal valid envelope (mirrors the §8.4 example shape)."""
    now = datetime.now(timezone.utc)
    envelope: dict[str, object] = {
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
        "idempotency_key": str(uuid4()),
        "correlation_id": "corr-12345678",
        "ticket_id": "TICKET-1",
        "requested_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "nonce": "nonce-12345678",
        "requested_by": "test-caller",
    }
    envelope.update(overrides)
    return envelope


def test_valid_envelope_accepted() -> None:
    """A well-formed envelope validates and round-trips its capability."""
    assert validate_envelope(_valid_envelope())["capability"] == "group.member.add"


def test_unknown_fields_rejected() -> None:
    """Unknown fields are rejected (schema_version contract is strict)."""
    with pytest.raises((ValidationError, ValueError)):
        validate_envelope(_valid_envelope(powershell="whoami"))


def test_expired_envelope_rejected() -> None:
    """Expired envelopes are rejected without dispatch."""
    now = datetime.now(timezone.utc)
    with pytest.raises((ValidationError, ValueError)):
        validate_envelope(
            _valid_envelope(
                requested_at=(now - timedelta(minutes=10)).isoformat(),
                expires_at=(now - timedelta(minutes=5)).isoformat(),
            )
        )


def test_inverted_validity_window_rejected() -> None:
    """expires_at <= requested_at is rejected (replay-window integrity)."""
    now = datetime.now(timezone.utc)
    with pytest.raises((ValidationError, ValueError)):
        validate_envelope(_valid_envelope(requested_at=now.isoformat(), expires_at=now.isoformat()))


def test_canonical_envelope_accepts_same_shape() -> None:
    """Canonical CommandEnvelope accepts the same valid envelope (track interop)."""
    module = pytest.importorskip(
        "mwa_ad_connector.application.commands.envelope", reason="Commands track (Step 10/16) has not landed yet."
    )
    model_cls = getattr(module, "CommandEnvelope", None)
    if model_cls is None:
        pytest.skip("Canonical envelope model differs: align tracks.")
    model = model_cls(**_valid_envelope())
    assert model.capability == "group.member.add"
    assert model.target.has_stable_identity is True
    # Local fallback agrees on the same input (dual-path consistency).
    assert validate_envelope(_valid_envelope())["capability"] == "group.member.add"
