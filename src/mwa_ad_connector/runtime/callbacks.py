"""Mutation planning and capability callback dispatch."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.application.services.account_service import AccountService
from mwa_ad_connector.application.services.group_membership_service import GroupMembershipService
from mwa_ad_connector.application.services.group_service import GroupService
from mwa_ad_connector.application.services.operation_service import MutateFn, VerifyFn
from mwa_ad_connector.application.services.ou_service import OuService
from mwa_ad_connector.application.services.password_service import PasswordService
from mwa_ad_connector.application.services.user_service import UserService
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.domain.errors import ProtectedTargetError, RequestInvalidError, TargetNotFoundError
from mwa_ad_connector.domain.evidence import VerificationEvidence
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.policy.scopes import ScopeChecker
from mwa_ad_connector.runtime import callbacks_accounts, callbacks_groups, callbacks_ous, callbacks_users
from mwa_ad_connector.runtime.adapters import Clock
from mwa_ad_connector.runtime.errors import OutOfScopeError
from mwa_ad_connector.runtime.params import (
    GROUP_TARGETS,
    MOVE_TARGETS,
    OU_TARGETS,
    SECRET_PARAMETER_KEYS,
    USER_TARGETS,
    MutationPlan,
    OutcomeTracker,
    attributes_param,
    destination_dn,
    group_type_value,
    opt_str,
    required_str,
    uuid_param,
)

EvidenceFn = Callable[..., VerificationEvidence]


class MutationCallbacks:
    """Resolve targets and build capability-specific mutate/verify callbacks.

    Args:
        gateway: Canonical directory gateway.
        settings: Local connector settings (scope + defaults).
        clock: Clock used for evidence timestamps.
        scope_checker: Configured DN scope checker.
    """

    def __init__(
        self,
        gateway: DirectoryGateway,
        settings: ConnectorSettings,
        clock: Clock,
        scope_checker: ScopeChecker,
    ) -> None:
        self._gateway = gateway
        self._settings = settings
        self._clock = clock
        self._scope_checker = scope_checker
        self._membership = GroupMembershipService(gateway)
        self._accounts = AccountService(gateway)
        self._passwords = PasswordService(gateway)
        self._users = UserService(gateway)
        self._groups = GroupService(gateway)
        self._ous = OuService(gateway)

    @property
    def _source_dc(self) -> str:
        """Return the pinned DC label reported by the gateway."""
        return str(getattr(self._gateway, "source_dc", "") or "unknown")

    def _evidence(
        self,
        verification_type: str,
        guid: UUID,
        dn: str,
        matched: bool,
        *,
        source_dc: str | None = None,
    ) -> VerificationEvidence:
        """Build redacted verification evidence for one check."""
        return VerificationEvidence(
            verification_type=verification_type,
            source_dc=source_dc or self._source_dc,
            observed_at=self._clock.now(),
            object_guid=guid,
            dn=dn or f"GUID={guid}",
            matched=matched,
            redaction_applied=True,
        )

    @staticmethod
    def request_parameters(parameters: Mapping[str, Any]) -> dict[str, Any]:
        """Project request parameters for the envelope (secrets excluded)."""
        return {str(key): value for key, value in parameters.items() if key not in SECRET_PARAMETER_KEYS}

    def validate(self, capability: str, parameters: Mapping[str, Any]) -> None:
        """Validate required capability parameters before any store write."""
        if capability in ("group.member.add", "group.member.remove"):
            uuid_param(parameters, "member_guid")
        if capability == "account.password.reset":
            required_str(parameters, "new_password")
        if capability in ("user.rename", "group.rename", "ou.rename"):
            required_str(parameters, "new_rdn")
        if capability in MOVE_TARGETS:
            destination_dn(capability, parameters)
        if capability in ("user.attributes.update", "group.attributes.update"):
            attributes_param(parameters)
        if capability == "user.create":
            required_str(parameters, "sam_account_name")
        if capability in ("user.create", "group.create"):
            required_str(parameters, "parent_ou")
        if capability == "ou.create":
            required_str(parameters, "parent")
        if capability == "group.create":
            group_type_value(required_str(parameters, "scope"), opt_str(parameters.get("category")) or "SECURITY")

    async def plan(self, capability: str, ref: ObjectReference, parameters: Mapping[str, Any]) -> MutationPlan:
        """Resolve the preflight target (and destination) for a mutation.

        Args:
            capability: Allowlisted mutation capability.
            ref: Target object reference.
            parameters: Validated request parameters.

        Returns:
            Resolved mutation plan.

        Raises:
            TargetNotFoundError: When the target (or member) does not exist.
            ProtectedTargetError: When the target is a privileged group.
            OutOfScopeError: When a move destination is out of scope.
            RequestInvalidError: On unsupported capabilities or missing GUIDs.
        """
        if capability in ("user.create", "group.create"):
            parent = required_str(parameters, "parent_ou")
            return MutationPlan(target_dn=parent, target_kind="ou", target_attrs={"dn": parent})
        if capability == "ou.create":
            parent = required_str(parameters, "parent")
            return MutationPlan(target_dn=parent, target_kind="ou", target_attrs={"dn": parent})
        guid = self._require_guid(ref)
        plan = await self._resolve_existing(capability, guid)
        if capability in ("group.member.add", "group.member.remove"):
            member_guid = uuid_param(parameters, "member_guid")
            if await self._gateway.resolve_by_guid(member_guid) is None:
                raise TargetNotFoundError("member target not found")
        if capability in MOVE_TARGETS:
            destination = destination_dn(capability, parameters)
            reason = self._scope_checker.check(ref.domain_id, destination)
            if reason is not None:
                raise OutOfScopeError(reason)
            return MutationPlan(
                target_dn=plan.target_dn,
                target_kind=plan.target_kind,
                target_attrs=plan.target_attrs,
                destination_dn=destination,
            )
        return plan

    @staticmethod
    def _require_guid(ref: ObjectReference) -> UUID:
        """Return the target GUID or fail with a request error."""
        if ref.object_guid is None:
            raise RequestInvalidError("mutations require target object_guid")
        return ref.object_guid

    async def _resolve_existing(self, capability: str, guid: UUID) -> MutationPlan:
        """Resolve the current DN and protected-target attrs for a target GUID."""
        if capability in USER_TARGETS:
            user = await self._gateway.get_user(guid)
            if user is None:
                raise TargetNotFoundError(f"target not found: {guid}")
            return MutationPlan(
                target_dn=user.distinguished_name,
                target_kind="user",
                target_attrs={"dn": user.distinguished_name, "sam_account_name": user.sam_account_name},
            )
        if capability in GROUP_TARGETS:
            group = await self._gateway.get_group(guid)
            if group is None:
                raise TargetNotFoundError(f"target not found: {guid}")
            if group.is_privileged:
                reasons = "; ".join(group.protection_reasons) or "policy"
                raise ProtectedTargetError(f"protected group: {reasons}")
            return MutationPlan(
                target_dn=group.distinguished_name,
                target_kind="group",
                target_attrs={
                    "dn": group.distinguished_name,
                    "sam_account_name": group.sam_account_name,
                    "name": group.name,
                },
            )
        if capability in OU_TARGETS:
            ou = await self._gateway.get_ou(guid)
            if ou is None:
                raise TargetNotFoundError(f"target not found: {guid}")
            return MutationPlan(
                target_dn=ou.distinguished_name,
                target_kind="ou",
                target_attrs={"dn": ou.distinguished_name},
            )
        raise RequestInvalidError(f"unsupported mutation capability: {capability}")

    def build(  # noqa: PLR0911 - flat capability dispatch stays readable.
        self,
        capability: str,
        ref: ObjectReference,
        parameters: Mapping[str, Any],
        tracker: OutcomeTracker,
    ) -> tuple[MutateFn, VerifyFn]:
        """Build the mutate/verify callbacks for one capability.

        Args:
            capability: Allowlisted mutation capability.
            ref: Target object reference (GUID required except creates).
            parameters: Validated request parameters.
            tracker: Mutable disposition holder updated by the mutate callback.

        Returns:
            Tuple of async callbacks for the orchestrator.

        Raises:
            RequestInvalidError: On unsupported capabilities.
        """
        if capability in ("group.member.add", "group.member.remove"):
            return callbacks_accounts.build_membership_callbacks(
                capability,
                ref,
                parameters,
                tracker,
                gateway=self._gateway,
                membership=self._membership,
                evidence=self._evidence,
            )
        if capability.startswith("account."):
            return callbacks_accounts.build_account_callbacks(
                capability,
                ref,
                parameters,
                tracker,
                gateway=self._gateway,
                accounts=self._accounts,
                passwords=self._passwords,
                evidence=self._evidence,
            )
        if capability.startswith("user."):
            return callbacks_users.build_user_callbacks(
                capability,
                ref,
                parameters,
                tracker,
                gateway=self._gateway,
                users=self._users,
                evidence=self._evidence,
            )
        if capability.startswith("group."):
            return callbacks_groups.build_group_callbacks(
                capability,
                ref,
                parameters,
                tracker,
                gateway=self._gateway,
                groups=self._groups,
                evidence=self._evidence,
            )
        if capability.startswith("ou."):
            return callbacks_ous.build_ou_callbacks(
                capability,
                ref,
                parameters,
                tracker,
                gateway=self._gateway,
                ous=self._ous,
                evidence=self._evidence,
            )
        raise RequestInvalidError(f"unsupported mutation capability: {capability}")
