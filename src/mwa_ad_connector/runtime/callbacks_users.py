"""User lifecycle (mutate, verify) callback builders."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import AttributeMap, DirectoryGateway
from mwa_ad_connector.application.services.operation_service import MutateFn, MutationParts, VerifyFn
from mwa_ad_connector.application.services.user_service import UserService
from mwa_ad_connector.domain.errors import RequestInvalidError
from mwa_ad_connector.domain.evidence import VerificationEvidence
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.runtime.params import (
    OutcomeTracker,
    attributes_param,
    destination_dn,
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


def build_user_callbacks(
    capability: str,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
    *,
    gateway: DirectoryGateway,
    users: UserService,
    evidence: EvidenceFn,
) -> Callbacks:
    """Dispatch user capability callback construction.

    Args:
        capability: User mutation capability.
        ref: Target object reference.
        parameters: Validated request parameters.
        tracker: Mutable disposition holder.
        gateway: Canonical directory gateway.
        users: User lifecycle service.
        evidence: Evidence factory bound to the runtime clock.

    Returns:
        Tuple of async mutate/verify callbacks.

    Raises:
        RequestInvalidError: On unsupported capabilities.
    """
    if capability == "user.attributes.update":
        return _attributes(gateway, users, evidence, ref, parameters, tracker)
    if capability == "user.create":
        return _create(gateway, users, evidence, parameters, tracker)
    if capability == "user.rename":
        return _rename(gateway, users, evidence, ref, parameters, tracker)
    if capability == "user.move":
        return _move(gateway, users, evidence, ref, parameters, tracker)
    if capability == "user.delete":
        return _delete(gateway, users, evidence, ref, tracker)
    raise RequestInvalidError(f"unsupported user capability: {capability}")


def _attributes(
    gateway: DirectoryGateway,
    users: UserService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build user attribute update callbacks."""
    user_guid = _require_guid(ref)
    attributes = attributes_param(parameters)
    expected_version = opt_str(parameters.get("expected_version"))
    desired = {
        key: ([value] if isinstance(value, str) else [str(item) for item in value]) for key, value in attributes.items()
    }

    async def mutate() -> MutationParts:
        before = await gateway.get_user(user_guid)
        outcome = await users.update_attributes(user_guid, attributes, expected_version)
        tracker.disposition = outcome.disposition
        after = await gateway.get_user(user_guid)
        return MutationParts(
            target_guid=user_guid,
            dn_before=outcome.dn_before or (before.distinguished_name if before else None),
            dn_after=outcome.dn_after or (after.distinguished_name if after else None),
            changed_fields=list(outcome.changed_fields),
            target_upn=after.user_principal_name if after else None,
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_user(user_guid)
        observed = after.attributes if after is not None else {}
        matched = after is not None and all(
            ([observed.get(key)] if isinstance(observed.get(key), str) else list(observed.get(key) or [])) == want
            for key, want in desired.items()
        )
        return evidence(
            "ATTRIBUTES_UPDATED",
            user_guid,
            after.distinguished_name if after else "",
            matched,
            source_dc=after.source_dc if after else None,
        )

    return mutate, verify


def _create(
    gateway: DirectoryGateway,
    users: UserService,
    evidence: EvidenceFn,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build user creation callbacks."""
    parent_dn = required_str(parameters, "parent_ou")
    attributes: AttributeMap = {"sAMAccountName": required_str(parameters, "sam_account_name")}
    if opt_str(parameters.get("user_principal_name")):
        attributes["userPrincipalName"] = required_str(parameters, "user_principal_name")
    if opt_str(parameters.get("display_name")):
        attributes["displayName"] = required_str(parameters, "display_name")
    extra = parameters.get("attributes")
    if isinstance(extra, Mapping):
        for key, value in extra.items():
            attributes[str(key)] = value if isinstance(value, str) else [str(item) for item in value]
    created: dict[str, UUID] = {}

    async def mutate() -> MutationParts:
        outcome = await users.create(parent_dn, attributes)
        created["guid"] = outcome.user_guid
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=outcome.user_guid,
            dn_before=None,
            dn_after=outcome.dn_after,
            changed_fields=["create"],
            target_upn=opt_str(attributes.get("userPrincipalName")),
        )

    async def verify() -> VerificationEvidence:
        guid = created.get("guid", UUID(int=0))
        user = await gateway.get_user(guid)
        return evidence(
            "USER_CREATED",
            guid,
            user.distinguished_name if user else "",
            user is not None and user.object_guid == guid,
            source_dc=user.source_dc if user else None,
        )

    return mutate, verify


def _rename(
    gateway: DirectoryGateway,
    users: UserService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build user rename callbacks."""
    user_guid = _require_guid(ref)
    new_rdn = required_str(parameters, "new_rdn")

    async def mutate() -> MutationParts:
        before = await gateway.get_user(user_guid)
        outcome = await users.rename(user_guid, new_rdn)
        tracker.disposition = outcome.disposition
        after = await gateway.get_user(user_guid)
        return MutationParts(
            target_guid=user_guid,
            dn_before=outcome.dn_before or (before.distinguished_name if before else None),
            dn_after=outcome.dn_after,
            changed_fields=list(outcome.changed_fields),
            target_upn=after.user_principal_name if after else None,
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_user(user_guid)
        return evidence(
            "USER_RENAMED",
            user_guid,
            after.distinguished_name if after else "",
            after is not None and after.object_guid == user_guid,
            source_dc=after.source_dc if after else None,
        )

    return mutate, verify


def _move(
    gateway: DirectoryGateway,
    users: UserService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build user move callbacks."""
    user_guid = _require_guid(ref)
    destination = destination_dn("user.move", parameters)

    async def mutate() -> MutationParts:
        outcome = await users.move(user_guid, destination)
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=user_guid,
            dn_before=outcome.dn_before,
            dn_after=outcome.dn_after,
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_user(user_guid)
        return evidence(
            "USER_MOVED",
            user_guid,
            after.distinguished_name if after else "",
            after is not None and after.object_guid == user_guid,
            source_dc=after.source_dc if after else None,
        )

    return mutate, verify


def _delete(
    gateway: DirectoryGateway,
    users: UserService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build user delete callbacks (verification proves absence)."""
    user_guid = _require_guid(ref)

    async def mutate() -> MutationParts:
        before = await gateway.get_user(user_guid)
        outcome = await users.delete(user_guid)
        tracker.disposition = outcome.disposition
        return MutationParts(
            target_guid=user_guid,
            dn_before=outcome.dn_before or (before.distinguished_name if before else None),
            dn_after=None,
            changed_fields=list(outcome.changed_fields),
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_user(user_guid)
        return evidence("USER_DELETED", user_guid, "", after is None)

    return mutate, verify
