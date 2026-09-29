"""Read-after-write verification evidence (Section 6.8).

Evidence describes what was verified in AD on a pinned DC. It must
never claim Entra convergence; cloud sync status is owned by the
cloud-side poller.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class VerificationEvidence(BaseModel):
    """Proof of a read-after-write check performed on a single DC.

    Attributes:
        verification_type: Stable check name (e.g. GROUP_MEMBERSHIP_PRESENT).
        source_dc: DC that served both commit and verification read.
        observed_at: Verification read timestamp (timezone-aware).
        expected: Redacted expected attribute snapshot.
        observed: Redacted observed attribute snapshot.
        matched: Whether observed satisfies expected.
        attribute_hashes: Non-reversible hashes for sensitive comparisons.
        object_guid: Verified object identity.
        dn: DN observed at verification time.
        replication_metadata_hint: Opaque replication hint when available.
        redaction_applied: Always True for API/audit surfaces.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    verification_type: str = Field(min_length=1, max_length=128)
    source_dc: str = Field(min_length=1, max_length=256)
    observed_at: datetime
    expected: dict[str, str] = Field(default_factory=dict)
    observed: dict[str, str] = Field(default_factory=dict)
    matched: bool
    attribute_hashes: dict[str, str] = Field(default_factory=dict)
    object_guid: UUID
    dn: str = Field(min_length=1, max_length=512)
    replication_metadata_hint: str | None = Field(default=None, max_length=512)
    redaction_applied: bool = True


class EntraEvidenceHint(BaseModel):
    """Non-authoritative hints helping the cloud poller find the object.

    This hint carries correlation data only (e.g. UPN). It never asserts
    synchronization state or timing.

    Attributes:
        target_upn: UPN hint for Entra lookup when known.
        target_object_id_hint: Caller-side Entra object id hint when known.
        sync_scope_note: Free note about the expected sync scope.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_upn: str | None = Field(default=None, max_length=256)
    target_object_id_hint: str | None = Field(default=None, max_length=256)
    sync_scope_note: str | None = Field(default=None, max_length=512)
