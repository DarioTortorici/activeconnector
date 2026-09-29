"""Operation lifecycle state machine (Step 9, plan sections 3.3-3.4).

On-prem states: RECEIVED -> AUTHORIZED -> EXECUTING -> AD_COMMITTED ->
AD_VERIFIED (terminal on-prem, handed to the cloud as WAITING_ENTRA_SYNC).
Cloud states: WAITING_ENTRA_SYNC -> ENTRA_CONVERGED / FAILED / EXPIRED /
ESCALATED. FAILED and FAILED_VERIFICATION are terminal; states never
regress. This module mirrors ``domain.enums.OperationState`` (owned by
another agent); unify on it when available.
"""

from __future__ import annotations

from enum import StrEnum


class OperationState(StrEnum):
    """Lifecycle states of an operation (plan section 6.1)."""

    RECEIVED = "RECEIVED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    AD_COMMITTED = "AD_COMMITTED"
    AD_VERIFIED = "AD_VERIFIED"
    WAITING_ENTRA_SYNC = "WAITING_ENTRA_SYNC"
    ENTRA_CONVERGED = "ENTRA_CONVERGED"
    FAILED = "FAILED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    EXPIRED = "EXPIRED"
    ESCALATED = "ESCALATED"


class InvalidTransition(Exception):
    """Raised when an operation state transition is not legal."""

    def __init__(self, current: str, nxt: str) -> None:
        super().__init__(f"illegal operation transition: {current!r} -> {nxt!r}")
        self.code = "INVALID_TRANSITION"
        self.current = current
        self.next = nxt


# Legal forward transitions; terminal states have no outgoing edges.
TRANSITIONS: dict[OperationState, tuple[OperationState, ...]] = {
    OperationState.RECEIVED: (
        OperationState.AUTHORIZED,
        OperationState.FAILED,
        OperationState.EXPIRED,
    ),
    OperationState.AUTHORIZED: (
        OperationState.EXECUTING,
        OperationState.FAILED,
        OperationState.EXPIRED,
    ),
    OperationState.EXECUTING: (
        OperationState.AD_COMMITTED,
        OperationState.FAILED,
        OperationState.EXPIRED,
    ),
    OperationState.AD_COMMITTED: (
        OperationState.AD_VERIFIED,
        OperationState.FAILED_VERIFICATION,
        OperationState.FAILED,
        OperationState.EXPIRED,
    ),
    OperationState.AD_VERIFIED: (OperationState.WAITING_ENTRA_SYNC,),
    OperationState.WAITING_ENTRA_SYNC: (
        OperationState.ENTRA_CONVERGED,
        OperationState.FAILED,
        OperationState.EXPIRED,
        OperationState.ESCALATED,
    ),
    OperationState.ENTRA_CONVERGED: (),
    OperationState.FAILED: (),
    OperationState.FAILED_VERIFICATION: (),
    OperationState.EXPIRED: (),
    OperationState.ESCALATED: (),
}

TERMINAL_STATES: frozenset[OperationState] = frozenset(
    {
        OperationState.ENTRA_CONVERGED,
        OperationState.FAILED,
        OperationState.FAILED_VERIFICATION,
        OperationState.EXPIRED,
        OperationState.ESCALATED,
    }
)

# Terminal from the on-prem connector viewpoint (cloud continues separately).
ON_PREM_TERMINAL_STATES: frozenset[OperationState] = frozenset(
    {
        OperationState.AD_VERIFIED,
        OperationState.FAILED,
        OperationState.FAILED_VERIFICATION,
    }
)


def _coerce(state: OperationState | str) -> OperationState | None:
    if isinstance(state, OperationState):
        return state
    try:
        return OperationState(str(state))
    except ValueError:
        return None


def can_transition(current: OperationState | str, nxt: OperationState | str) -> bool:
    """Return True when moving from ``current`` to ``nxt`` is legal.

    Unknown state names and any move out of a terminal state return False.
    """
    source = _coerce(current)
    target = _coerce(nxt)
    if source is None or target is None:
        return False
    return target in TRANSITIONS[source]


def is_terminal(state: OperationState | str) -> bool:
    """Return True when ``state`` is terminal (no outgoing transitions)."""
    coerced = _coerce(state)
    return coerced is not None and coerced in TERMINAL_STATES


def advance(current: OperationState | str, nxt: OperationState | str) -> OperationState:
    """Move from ``current`` to ``nxt`` or raise :class:`InvalidTransition`."""
    if not can_transition(current, nxt):
        raise InvalidTransition(str(current), str(nxt))
    target = _coerce(nxt)
    if target is None:  # pragma: no cover - guarded by can_transition
        raise InvalidTransition(str(current), str(nxt))
    return target
