"""Membership and account (mutate, verify) callback builders."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from uuid import UUID

from pydantic import SecretStr

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.application.services.account_service import AccountService
from mwa_ad_connector.application.services.group_membership_service import GroupMembershipService
from mwa_ad_connector.application.services.operation_service import MutateFn, MutationParts, VerifyFn
from mwa_ad_connector.application.services.password_service import PasswordService
from mwa_ad_connector.domain.errors import RequestInvalidError
from mwa_ad_connector.domain.evidence import VerificationEvidence
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.runtime.params import OutcomeTracker, opt_str, required_str, uuid_param

EvidenceFn = Callable[..., VerificationEvidence]
Callbacks = tuple[MutateFn, VerifyFn]


def _require_guid(ref: ObjectReference) -> UUID:
    """Return the target GUID or fail with a request error."""
    if ref.object_guid is None:
        raise RequestInvalidError("mutations require target object_guid")
    return ref.object_guid


def build_membership_callbacks(
    capability: str,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
    *,
    gateway: DirectoryGateway,
    membership: GroupMembershipService,
    evidence: EvidenceFn,
) -> Callbacks:
    """Build add/remove membership callbacks."""
    group_guid = _require_guid(ref)
    member_guid = uuid_param(parameters, "member_guid")
    expected_version = opt_str(parameters.get("expected_version"))
    adding = capability == "group.member.add"

    async def mutate() -> MutationParts:
        before = await gateway.get_group(group_guid)
        if adding:
            outcome = await membership.add(group_guid, member_guid, expected_version)
        else:
            outcome = await membership.remove(group_guid, member_guid)
        tracker.disposition = outcome.disposition
        after = await gateway.get_group(group_guid)
        return MutationParts(
            target_guid=group_guid,
            dn_before=before.distinguished_name if before else None,
            dn_after=after.distinguished_name if after else None,
            changed_fields=["member"],
        )

    async def verify() -> VerificationEvidence:
        members = await gateway.list_group_members(group_guid)
        group = await gateway.get_group(group_guid)
        present = member_guid in members
        return evidence(
            "GROUP_MEMBERSHIP_PRESENT" if adding else "GROUP_MEMBERSHIP_ABSENT",
            group_guid,
            group.distinguished_name if group else "",
            present if adding else not present,
        )

    return mutate, verify


def build_account_callbacks(
    capability: str,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
    *,
    gateway: DirectoryGateway,
    accounts: AccountService,
    passwords: PasswordService,
    evidence: EvidenceFn,
) -> Callbacks:
    """Dispatch account capability callback construction.

    Args:
        capability: Account mutation capability.
        ref: Target object reference.
        parameters: Validated request parameters.
        tracker: Mutable disposition holder.
        gateway: Canonical directory gateway.
        accounts: Account state service.
        passwords: Password service (secret-safe).
        evidence: Evidence factory bound to the runtime clock.

    Returns:
        Tuple of async mutate/verify callbacks.

    Raises:
        RequestInvalidError: On unsupported capabilities.
    """
    if capability == "account.unlock":
        return _unlock(gateway, accounts, evidence, ref, tracker)
    if capability in ("account.enable", "account.disable"):
        return _enabled(gateway, accounts, evidence, capability, ref, parameters, tracker)
    if capability == "account.password.reset":
        return _password_reset(gateway, passwords, evidence, ref, parameters, tracker)
    if capability == "account.password.force_change":
        return _force_change(gateway, passwords, evidence, ref, parameters, tracker)
    raise RequestInvalidError(f"unsupported account capability: {capability}")


def _unlock(
    gateway: DirectoryGateway,
    accounts: AccountService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build the unlock callbacks."""
    user_guid = _require_guid(ref)

    async def mutate() -> MutationParts:
        before = await gateway.get_user(user_guid)
        outcome = await accounts.unlock(user_guid)
        tracker.disposition = outcome.disposition
        after = await gateway.get_user(user_guid)
        return MutationParts(
            target_guid=user_guid,
            dn_before=before.distinguished_name if before else None,
            dn_after=after.distinguished_name if after else None,
            changed_fields=list(outcome.changed_fields),
            target_upn=after.user_principal_name if after else None,
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_user(user_guid)
        return evidence(
            "ACCOUNT_UNLOCKED",
            user_guid,
            after.distinguished_name if after else "",
            after is not None and not after.locked,
        )

    return mutate, verify


def _enabled(
    gateway: DirectoryGateway,
    accounts: AccountService,
    evidence: EvidenceFn,
    capability: str,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build enable/disable callbacks."""
    user_guid = _require_guid(ref)
    enable = capability == "account.enable"
    expected_version = opt_str(parameters.get("expected_version"))

    async def mutate() -> MutationParts:
        before = await gateway.get_user(user_guid)
        outcome = await accounts.set_enabled(user_guid, enable, expected_version)
        tracker.disposition = outcome.disposition
        after = await gateway.get_user(user_guid)
        return MutationParts(
            target_guid=user_guid,
            dn_before=before.distinguished_name if before else None,
            dn_after=after.distinguished_name if after else None,
            changed_fields=list(outcome.changed_fields),
            target_upn=after.user_principal_name if after else None,
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_user(user_guid)
        return evidence(
            "ACCOUNT_ENABLED" if enable else "ACCOUNT_DISABLED",
            user_guid,
            after.distinguished_name if after else "",
            after is not None and after.enabled == enable,
        )

    return mutate, verify


def _password_reset(
    gateway: DirectoryGateway,
    passwords: PasswordService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build the password reset callbacks (secret never leaves the closure)."""
    user_guid = _require_guid(ref)
    password = SecretStr(required_str(parameters, "new_password"))
    force_change = bool(parameters.get("force_change_at_logon", True))

    async def mutate() -> MutationParts:
        before = await gateway.get_user(user_guid)
        outcome = await passwords.reset(user_guid, password)
        tracker.disposition = "APPLIED"
        changed = list(outcome.changed_fields)
        if force_change:
            await passwords.force_change(user_guid, True)
            changed.append("pwdLastSet")
        after = await gateway.get_user(user_guid)
        return MutationParts(
            target_guid=user_guid,
            dn_before=before.distinguished_name if before else None,
            dn_after=after.distinguished_name if after else None,
            changed_fields=changed,
            target_upn=after.user_principal_name if after else None,
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_user(user_guid)
        return evidence(
            "PASSWORD_RESET",
            user_guid,
            after.distinguished_name if after else "",
            after is not None,
        )

    return mutate, verify


def _force_change(
    gateway: DirectoryGateway,
    passwords: PasswordService,
    evidence: EvidenceFn,
    ref: ObjectReference,
    parameters: Mapping[str, Any],
    tracker: OutcomeTracker,
) -> Callbacks:
    """Build the force-password-change callbacks."""
    user_guid = _require_guid(ref)
    force = bool(parameters.get("force", True))

    async def mutate() -> MutationParts:
        before = await gateway.get_user(user_guid)
        outcome = await passwords.force_change(user_guid, force)
        tracker.disposition = "APPLIED"
        after = await gateway.get_user(user_guid)
        return MutationParts(
            target_guid=user_guid,
            dn_before=before.distinguished_name if before else None,
            dn_after=after.distinguished_name if after else None,
            changed_fields=list(outcome.changed_fields),
            target_upn=after.user_principal_name if after else None,
        )

    async def verify() -> VerificationEvidence:
        after = await gateway.get_user(user_guid)
        return evidence(
            "PASSWORD_FORCE_CHANGE",
            user_guid,
            after.distinguished_name if after else "",
            after is not None,
        )

    return mutate, verify
