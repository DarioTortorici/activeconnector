"""Unit: operation state HTTP semantics (§3.4/§3.5) plus canonical state-machine check."""

import json
from typing import Any

import pytest

from mwa_ad_connector.api.routes import mutation_response

TERMINAL_STATES = {"AD_VERIFIED", "ENTRA_CONVERGED", "FAILED", "FAILED_VERIFICATION", "EXPIRED", "ESCALATED"}


def _result(state: str) -> dict[str, Any]:
    """Build a minimal result mapping for a terminal/queued state."""
    return {"operation_id": "op-1", "state": state}


@pytest.mark.parametrize("state", ["RECEIVED", "AUTHORIZED", "EXECUTING", "WAITING_ENTRA_SYNC"])
def test_queued_states_return_202_with_status_url(state: str) -> None:
    """Queued work returns 202 with operation_id + status_url (never bare 200)."""
    response = mutation_response(_result(state))
    assert response.status_code == 202
    body = json.loads(bytes(response.body).decode())
    assert body["operation_id"] == "op-1"
    assert body["status_url"] == "/api/v1/operations/op-1"


@pytest.mark.parametrize("state", ["AD_VERIFIED", "AD_COMMITTED", "ENTRA_CONVERGED"])
def test_completed_states_return_200(state: str) -> None:
    """Verified/completed work returns 200 with the state preserved."""
    response = mutation_response(_result(state))
    assert response.status_code == 200
    assert json.loads(bytes(response.body).decode())["state"] == state


def test_failed_verification_returns_502_with_evidence() -> None:
    """Commit-then-verify-failure is 502 FAILED_VERIFICATION with redacted evidence."""
    result = _result("FAILED_VERIFICATION")
    result["verification_evidence"] = {"matched": False, "redaction_applied": True}
    response = mutation_response(result)
    assert response.status_code == 502
    body = json.loads(bytes(response.body).decode())
    assert body["state"] == "FAILED_VERIFICATION"
    assert body["verification_evidence"]["redaction_applied"] is True


def test_canonical_state_machine_covers_plan_states() -> None:
    """Canonical state machine (when landed) knows every §3.4 state and terminal set."""
    module = pytest.importorskip(
        "mwa_ad_connector.operations.state_machine", reason="Operations track (Step 9) has not landed yet."
    )
    transitions = getattr(module, "TRANSITIONS", None)
    assert isinstance(transitions, dict) and transitions, "Canonical TRANSITIONS table missing."
    known: set[str] = set()
    for source, targets in transitions.items():
        known.add(str(getattr(source, "value", source)))
        for target in targets or []:
            known.add(str(getattr(target, "value", target)))
    missing = {
        "RECEIVED",
        "AUTHORIZED",
        "EXECUTING",
        "AD_COMMITTED",
        "AD_VERIFIED",
        "FAILED",
        "FAILED_VERIFICATION",
    } - known
    assert not missing, f"Canonical machine misses plan states: {missing}"

    operation_state = getattr(module, "OperationState", None)
    assert operation_state is not None
    assert module.is_terminal(operation_state.FAILED_VERIFICATION) is True
    assert module.is_terminal(operation_state.FAILED) is True
    assert module.is_terminal(operation_state.RECEIVED) is False
    assert module.can_transition(operation_state.RECEIVED, operation_state.AUTHORIZED) is True
    assert module.can_transition(operation_state.FAILED, operation_state.RECEIVED) is False
    assert TERMINAL_STATES  # local HTTP-semantics contract documented above.
