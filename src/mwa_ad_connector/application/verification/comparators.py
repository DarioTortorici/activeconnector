"""Staged diff: minimal Add/Delete/Replace modifications (Step 9/13).

``staged_diff`` compares the observed attribute state against the desired
state and emits the smallest LDAP modify list. Multi-valued attributes
are handled per value: partial overlaps become Add/Delete pairs, full
replacements become a single Replace, so servers apply the minimal change.
Operates on decoded string values; binary attributes are out of scope.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AttributeOp = Literal["add", "delete", "replace"]


class StagedModification(BaseModel):
    """Single LDAP modify operation within a staged diff."""

    model_config = ConfigDict(extra="forbid")

    op: AttributeOp
    attribute: str = Field(min_length=1)
    values: list[str] = Field(default_factory=list)


def staged_diff(
    current: Mapping[str, Sequence[str]],
    desired: Mapping[str, Sequence[str] | None],
) -> list[StagedModification]:
    """Compute the minimal modify list from ``current`` to ``desired``.

    Args:
        current: Observed attribute values keyed by attribute name.
        desired: Desired values; ``None`` deletes the attribute, while an
            attribute absent from ``desired`` is left untouched (partial
            update semantics).

    Returns:
        Deterministic (attribute-sorted) modifications: Add for new
        values, Delete for removed ones, Replace for full disjoint
        changes. Empty when already converged.
    """
    modifications: list[StagedModification] = []
    for attribute in sorted(set(current) | set(desired)):
        if attribute not in desired:
            continue
        wanted = desired[attribute]
        present = set(current.get(attribute, ()))
        if wanted is None:
            if present:
                modifications.append(StagedModification(op="delete", attribute=attribute, values=sorted(present)))
            continue
        target = set(wanted)
        added = sorted(target - present)
        removed = sorted(present - target)
        if not added and not removed:
            continue
        if not present:
            modifications.append(StagedModification(op="add", attribute=attribute, values=added))
        elif not target:
            modifications.append(StagedModification(op="delete", attribute=attribute, values=removed))
        elif added and removed and present.isdisjoint(target):
            modifications.append(StagedModification(op="replace", attribute=attribute, values=sorted(target)))
        else:
            if removed:
                modifications.append(StagedModification(op="delete", attribute=attribute, values=removed))
            if added:
                modifications.append(StagedModification(op="add", attribute=attribute, values=added))
    return modifications
