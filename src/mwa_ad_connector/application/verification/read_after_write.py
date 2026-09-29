"""Read-after-write verification on the same DC (Step 9).

After a mutation commits, the connector re-reads the object from the same
DC and compares the expected attribute state with the observed one. The
result is :class:`VerificationEvidence` (plan section 6.8): sufficient for
the cloud to know what AD confirmed, never a claim of Entra convergence.
Secret-bearing attributes are redacted; value digests prove observation
without disclosing values.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.application.verification.comparators import StagedModification, staged_diff
from mwa_ad_connector.security.redaction import attribute_hashes, redact_dict


class VerificationEvidence(BaseModel):
    """Read-after-write outcome (plan section 6.8)."""

    model_config = ConfigDict(extra="forbid")

    verification_type: str = Field(min_length=1)
    source_dc: str = Field(min_length=1)
    observed_at: datetime
    expected: dict[str, list[str]] = Field(default_factory=dict)
    observed: dict[str, list[str]] = Field(default_factory=dict)
    matched: bool
    attribute_hashes: dict[str, list[str]] = Field(default_factory=dict)
    object_guid: str = Field(min_length=1)
    dn: str = Field(min_length=1)
    replication_metadata_hint: str | None = None
    redaction_applied: bool = True


class DirectoryReader(Protocol):
    """Minimal read port for verification (subset of DirectoryGateway)."""

    async def read_attributes(self, *, object_guid: str, dc: str | None = None) -> Mapping[str, Any] | None:
        """Return observed attributes for ``object_guid`` read from ``dc``."""
        ...  # pragma: no cover


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value.decode("utf-8", errors="strict") if isinstance(value, bytes) else value]
    if isinstance(value, Sequence):
        items: list[str] = []
        for item in value:
            if isinstance(item, bytes):
                items.append(item.decode("utf-8", errors="strict"))
            else:
                items.append(str(item))
        return items
    return [str(value)]


async def verify_with_same_dc(  # noqa: PLR0913 - explicit verification dimensions
    *,
    reader: DirectoryReader,
    object_guid: str,
    dn: str,
    expected: Mapping[str, Sequence[str]],
    dc: str,
    verification_type: str = "READ_AFTER_WRITE",
    now: datetime | None = None,
) -> VerificationEvidence:
    """Re-read from ``dc`` and compare against ``expected``.

    A missing object (reader returns None) yields ``matched=False``
    evidence rather than an exception, so the caller can transition to
    FAILED_VERIFICATION with full context.
    """
    observed_raw = await reader.read_attributes(object_guid=object_guid, dc=dc)
    observed: dict[str, list[str]] = {
        name: _as_str_list(observed_raw.get(name)) if observed_raw is not None else [] for name in expected
    }
    mismatches: list[StagedModification] = staged_diff(observed, dict(expected))
    matched = not mismatches
    expected_clean = {name: sorted(values) for name, values in expected.items()}
    return VerificationEvidence(
        verification_type=verification_type,
        source_dc=dc,
        observed_at=now or datetime.now(UTC),
        expected=dict(redact_dict(expected_clean)),
        observed=dict(redact_dict(observed)),
        matched=matched,
        attribute_hashes=attribute_hashes(observed),
        object_guid=object_guid,
        dn=dn,
        redaction_applied=True,
    )
