"""Group lifecycle (mutate, verify) callback builders."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, cast
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import AttributeMap, DirectoryGateway
from mwa_ad_connector.application.services.group_service import GroupService
from mwa_ad_connector.application.services.operation_service import MutateFn, MutationParts, VerifyFn
from mwa_ad_connector.domain.errors import RequestInvalidError
from mwa_ad_connector.domain.evidence import VerificationEvidence
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.runtime.params import (
    OutcomeTracker,
    attributes_param,
    destination_dn,
    group_type_value,
    opt_str,
    required_str,
)

EvidenceFn = Callable[..., VerificationEvidence]
Callbacks = tuple[MutateFn, VerifyFn]


def _require_guid(ref: ObjectReference) -> UUID:
    """Return the target GUID or fail with a request error."""
    if ref.object_guid is None:
        raise RequestInvalidError("mutations require target object_guid")
    return ref.object_guid


def build_group_callbacks(
    capability: str,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
    *,
    gateway: DirectoryGateway,
    groups: GroupService,
    evidence: EvidenceFn,
) -> Callbacks:
    """Dispatch group capability callback construction.

    Args:
        capability: Group mutation capability.
        ref: Target object reference.
        parameters: Validated request parameters.
        tracker: Mutable disposition holder.
        gateway: Canonical directory gateway.
        groups: Group lifecycle service.
        evidence: Evidence factory bound to the runtime clock.

    Returns:
        Tuple of async mutate/verify callbacks.

    Raises:
        RequestInvalidError: On unsupported capabilities.
    """
    if capability == "group.attributes.update":
        return _attributes(gateway, groups, evidence, ref, parameters, tracker)
    if capability == "group.create":
        return _create(gateway, groups, evidence, parameters, tracker)
    if capability == "group.rename":
        return _rename(gateway, groups, evidence, ref, parameters, tracker)
    if capability == "group.move":
        return _move(gateway, groups, evidence, ref, parameters, tracker)
    if capability == "group.delete":
        return _delete(gateway, groups, evidence, ref, tracker)
    raise RequestInvalidError(f"unsupported group capability: {capability}")


def _attributes(
    gateway: DirectoryGateway,
    groups: GroupService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build group attribute update callbacks."""
    group_guid = _require_guid(ref)
    attributes = attributes_param(parameters)
    expected_version = opt_str(parameters.get("expected_version"))

    async def mutate() -> MutationParts:
        before = await gateway.get_group(group_guid)
        outcome = await groups.update_attributes(group_guid, attributes, expected_version)
        tracker.disposition = outcome.disposition
        after = await gateway.get_group(group_guid)
        return MutationParts(
            target_guid=group_guid,
            dn_before=outcome.dn_before or (before.distinguished_name if before else None),
            dn_after=outcome.dn_after or (after.distinguished_name if after else None),
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_group(group_guid)
        return evidence(
            "GROUP_ATTRIBUTES_UPDATED",
            group_guid,
            after.distinguished_name if after else "",
            after is not None and after.object_guid == group_guid,
            source_dc=after.source_dc if after else None,
        )

    return mutate, verify


def _create(
    gateway: DirectoryGateway,
    groups: GroupService,
    evidence: EvidenceFn,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build group creation callbacks."""
    parent_dn = required_str(parameters, "parent_ou")
    attributes: dict[str, Any] = {
        "name": required_str(parameters, "name"),
        "groupType": group_type_value(
            required_str(parameters, "scope"), opt_str(parameters.get("category")) or "SECURITY"
        ),
    }
    if opt_str(parameters.get("description")):
        attributes["description"] = required_str(parameters, "description")
    created: dict[str, UUID] = {}

    async def mutate() -> MutationParts:
        outcome = await groups.create(parent_dn, cast(AttributeMap, attributes))
        created["guid"] = outcome.group_guid
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=outcome.group_guid,
            dn_before=None,
            dn_after=outcome.dn_after,
            changed_fields=["create"],
        )

    async def verify() -> VerificationEvidence:
        guid = created.get("guid", UUID(int=0))
        group = await gateway.get_group(guid)
        return evidence(
            "GROUP_CREATED",
            guid,
            group.distinguished_name if group else "",
            group is not None and group.object_guid == guid,
            source_dc=group.source_dc if group else None,
        )

    return mutate, verify


def _rename(
    gateway: DirectoryGateway,
    groups: GroupService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build group rename callbacks."""
    group_guid = _require_guid(ref)
    new_rdn = required_str(parameters, "new_rdn")

    async def mutate() -> MutationParts:
        before = await gateway.get_group(group_guid)
        outcome = await groups.rename(group_guid, new_rdn)
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=group_guid,
            dn_before=outcome.dn_before or (before.distinguished_name if before else None),
            dn_after=outcome.dn_after,
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_group(group_guid)
        return evidence(
            "GROUP_RENAMED",
            group_guid,
            after.distinguished_name if after else "",
            after is not None and after.object_guid == group_guid,
            source_dc=after.source_dc if after else None,
        )

    return mutate, verify


def _move(
    gateway: DirectoryGateway,
    groups: GroupService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build group move callbacks."""
    group_guid = _require_guid(ref)
    destination = destination_dn("group.move", parameters)

    async def mutate() -> MutationParts:
        outcome = await groups.move(group_guid, destination)
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=group_guid,
            dn_before=outcome.dn_before,
            dn_after=outcome.dn_after,
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_group(group_guid)
        return evidence(
            "GROUP_MOVED",
            group_guid,
            after.distinguished_name if after else "",
            after is not None and after.object_guid == group_guid,
            source_dc=after.source_dc if after else None,
        )

    return mutate, verify


def _delete(
    gateway: DirectoryGateway,
    groups: GroupService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build group delete callbacks (verification proves absence)."""
    group_guid = _require_guid(ref)

    async def mutate() -> MutationParts:
        before = await gateway.get_group(group_guid)
        outcome = await groups.delete(group_guid)
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=group_guid,
            dn_before=outcome.dn_before or (before.distinguished_name if before else None),
            dn_after=None,
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_group(group_guid)
        return evidence("GROUP_DELETED", group_guid, "", after is None)

    return mutate, verify
