"""Retention: purge terminal operations older than a cutoff (Step 9)."""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from mwa_ad_connector.operations.state_machine import TERMINAL_STATES


class RetentionResult(BaseModel):
    """Outcome of a retention pass."""

    model_config = ConfigDict(extra="forbid")

    cutoff: datetime
    dry_run: bool
    checked: int
    purged: int
    terminal_states: list[str]


class SupportsPurge(Protocol):
    """Persistence port needed for retention."""

    async def count_terminal_before(self, cutoff: datetime, *, terminal_states: Collection[str]) -> int:
        """Count terminal records updated before ``cutoff``."""
        ...  # pragma: no cover

    async def purge_terminal_before(self, cutoff: datetime, *, terminal_states: Collection[str]) -> int:
        """Delete terminal records updated before ``cutoff``; return the count."""
        ...  # pragma: no cover


def default_terminal_states() -> list[str]:
    """Return the default terminal state names eligible for retention."""
    return sorted(state.value for state in TERMINAL_STATES)


async def apply_retention(
    store: SupportsPurge,
    *,
    cutoff: datetime,
    terminal_states: Collection[str] | None = None,
    dry_run: bool = False,
) -> RetentionResult:
    """Purge (or count, when ``dry_run``) terminal records older than ``cutoff``.

    Only terminal states are ever eligible; active operations are never
    touched regardless of age.
    """
    states = list(terminal_states) if terminal_states is not None else default_terminal_states()
    checked = await store.count_terminal_before(cutoff, terminal_states=states)
    purged = 0 if dry_run else await store.purge_terminal_before(cutoff, terminal_states=states)
    return RetentionResult(cutoff=cutoff, dry_run=dry_run, checked=checked, purged=purged, terminal_states=states)
