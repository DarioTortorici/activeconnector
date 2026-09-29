"""OU lifecycle (mutate, verify) callback builders."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.application.services.operation_service import MutateFn, MutationParts, VerifyFn
from mwa_ad_connector.application.services.ou_service import OuService
from mwa_ad_connector.domain.errors import RequestInvalidError
from mwa_ad_connector.domain.evidence import VerificationEvidence
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.runtime.params import OutcomeTracker, destination_dn, required_str

EvidenceFn = Callable[..., VerificationEvidence]
Callbacks = tuple[MutateFn, VerifyFn]


def _require_guid(ref: ObjectReference) -> UUID:
    """Return the target GUID or fail with a request error."""
    if ref.object_guid is None:
        raise RequestInvalidError("mutations require target object_guid")
    return ref.object_guid


def build_ou_callbacks(
    capability: str,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
    *,
    gateway: DirectoryGateway,
    ous: OuService,
    evidence: EvidenceFn,
) -> Callbacks:
    """Dispatch OU capability callback construction.

    Args:
        capability: OU mutation capability.
        ref: Target object reference.
        parameters: Validated request parameters.
        tracker: Mutable disposition holder.
        gateway: Canonical directory gateway.
        ous: OU lifecycle service.
        evidence: Evidence factory bound to the runtime clock.

    Returns:
        Tuple of async mutate/verify callbacks.

    Raises:
        RequestInvalidError: On unsupported capabilities.
    """
    if capability == "ou.create":
        return _create(gateway, ous, evidence, parameters, tracker)
    if capability == "ou.rename":
        return _rename(gateway, ous, evidence, ref, parameters, tracker)
    if capability == "ou.move":
        return _move(gateway, ous, evidence, ref, parameters, tracker)
    if capability == "ou.delete":
        return _delete(gateway, ous, evidence, ref, parameters, tracker)
    raise RequestInvalidError(f"unsupported ou capability: {capability}")


def _create(
    gateway: DirectoryGateway,
    ous: OuService,
    evidence: EvidenceFn,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build OU creation callbacks."""
    parent_dn = required_str(parameters, "parent")
    name = required_str(parameters, "name")
    created: dict[str, UUID] = {}

    async def mutate() -> MutationParts:
        outcome = await ous.create(parent_dn, name)
        created["guid"] = outcome.ou_guid
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=outcome.ou_guid,
            dn_before=None,
            dn_after=outcome.dn_after,
            changed_fields=["create"],
        )

    async def verify() -> VerificationEvidence:
        guid = created.get("guid", UUID(int=0))
        ou = await gateway.get_ou(guid)
        return evidence(
            "OU_CREATED",
            guid,
            ou.distinguished_name if ou else "",
            ou is not None and ou.object_guid == guid,
            source_dc=ou.source_dc if ou else None,
        )

    return mutate, verify


def _rename(
    gateway: DirectoryGateway,
    ous: OuService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build OU rename callbacks."""
    ou_guid = _require_guid(ref)
    new_rdn = required_str(parameters, "new_rdn")

    async def mutate() -> MutationParts:
        before = await gateway.get_ou(ou_guid)
        outcome = await ous.rename(ou_guid, new_rdn)
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=ou_guid,
            dn_before=outcome.dn_before or (before.distinguished_name if before else None),
            dn_after=outcome.dn_after,
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_ou(ou_guid)
        return evidence(
            "OU_RENAMED",
            ou_guid,
            after.distinguished_name if after else "",
            after is not None and after.object_guid == ou_guid,
            source_dc=after.source_dc if after else None,
        )

    return mutate, verify


def _move(
    gateway: DirectoryGateway,
    ous: OuService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build OU move callbacks."""
    ou_guid = _require_guid(ref)
    destination = destination_dn("ou.move", parameters)

    async def mutate() -> MutationParts:
        outcome = await ous.move(ou_guid, destination)
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=ou_guid,
            dn_before=outcome.dn_before,
            dn_after=outcome.dn_after,
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_ou(ou_guid)
        return evidence(
            "OU_MOVED",
            ou_guid,
            after.distinguished_name if after else "",
            after is not None and after.object_guid == ou_guid,
            source_dc=after.source_dc if after else None,
        )

    return mutate, verify


def _delete(
    gateway: DirectoryGateway,
    ous: OuService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build OU delete callbacks (empty-only by default)."""
    ou_guid = _require_guid(ref)
    require_empty = bool(parameters.get("require_empty", True))

    async def mutate() -> MutationParts:
        before = await gateway.get_ou(ou_guid)
        outcome = await ous.delete(ou_guid, require_empty)
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=ou_guid,
            dn_before=outcome.dn_before or (before.distinguished_name if before else None),
            dn_after=None,
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_ou(ou_guid)
        return evidence("OU_DELETED", ou_guid, "", after is None)

    return mutate, verify
