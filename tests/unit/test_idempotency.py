"""Unit: idempotency (worker dedup + key reservation + canonical cross-check)."""

import inspect
from typing import Any

import pytest

from mwa_ad_connector.api.error_handlers import CODE_TABLE, ConnectorError
from mwa_ad_connector.infrastructure.transport.worker import dedup_key


def test_dedup_key_scopes_tenant_connector_key() -> None:
    """Dedup key binds tenant+connector+idempotency key (no cross-boundary reuse)."""
    envelope = {"tenant_id": "t1", "connector_id": "c1", "idempotency_key": "k1"}
    assert dedup_key(envelope) == "t1|c1|k1"
    assert dedup_key({}) is None
    assert dedup_key({"tenant_id": "t1"}) is None


def test_idempotency_collision_code_is_409() -> None:
    """Same key + different payload is a 409 conflict (taxonomy-owned)."""
    category, http_status, _ = CODE_TABLE["IDEMPOTENCY_COLLISION"]
    assert (category, http_status) == ("CONFLICT", 409)


async def test_service_rejects_key_reuse_with_different_payload(fake_service: Any) -> None:
    """Fake (like the canonical store): key reuse with new payload collides."""
    service = fake_service
    target = {"object_type": "USER", "object_guid": "u-1"}
    base = {
        "capability": "account.unlock",
        "target": target,
        "parameters": {},
        "caller": {},
        "idempotency_key": "key-1",
        "correlation_id": "c",
        "ticket_id": "T1",
        "dry_run": False,
    }
    first = await service.execute_capability(**base)
    second = await service.execute_capability(**base)
    assert first["operation_id"] == second["operation_id"]

    base["parameters"] = {"reason": "different"}
    with pytest.raises(ConnectorError) as exc_info:
        await service.execute_capability(**base)
    assert exc_info.value.code == "IDEMPOTENCY_COLLISION"


def test_canonical_idempotency_surface() -> None:
    """Canonical idempotency helpers (when landed) expose reserve/check/hash entrypoints."""
    module = pytest.importorskip(
        "mwa_ad_connector.operations.idempotency", reason="Operations track (Step 9) has not landed yet."
    )
    assert callable(getattr(module, "reserve", None)), "reserve missing."
    assert callable(getattr(module, "check", None)), "check missing."
    assert callable(getattr(module, "canonical_request_hash", None)), "canonical_request_hash missing."
    reserve_params = set(inspect.signature(module.reserve).parameters)
    assert {"tenant_id", "connector_id", "idempotency_key", "request_hash"} <= reserve_params
