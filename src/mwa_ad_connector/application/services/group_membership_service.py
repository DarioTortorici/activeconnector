"""Group membership mutations with guards and same-DC verification."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.domain.errors import DomainError, ErrorCode, VerificationFailedError


class MembershipCycleError(DomainError):
    """Adding the member would create a nesting cycle."""

    code = ErrorCode.LDAP_CONSTRAINT_VIOLATION


@dataclass(frozen=True)
class MembershipOutcome:
    """Membership mutation result.

    Attributes:
        disposition: APPLIED or NO_OP.
        group_guid: Group GUID.
        member_guid: Member GUID.
        source_dc: DC that committed/verified.
        verified: Read-after-write confirmation flag.
    """

    disposition: str
    group_guid: UUID
    member_guid: UUID
    source_dc: str
    verified: bool


class GroupMembershipService:
    """Add/remove group members with cycle check and idempotent no-ops.

    The gateway instance is pinned to one DC, so commit and verification
    reads share the same source implicitly.

    Args:
        gateway: Canonical directory gateway.
    """

    def __init__(self, gateway: DirectoryGateway, max_nesting_depth: int = 10) -> None:
        self._gateway = gateway
        self._max_depth = max_nesting_depth

    async def _cycle_check(self, group_guid: UUID, member_guid: UUID) -> None:
        """Reject adds where group is (transitively) a member of member.

        Args:
            group_guid: Target group.
            member_guid: Candidate member.

        Raises:
            MembershipCycleError: On direct or transitive cycle.
        """
        if group_guid == member_guid:
            raise MembershipCycleError("self-membership is not allowed")
        if await self._gateway.get_group(member_guid) is None:
            return
        frontier = [member_guid]
        seen: set[UUID] = set()
        for _ in range(self._max_depth):
            nxt: list[UUID] = []
            for node in frontier:
                if node in seen:
                    continue
                seen.add(node)
                try:
                    members = await self._gateway.list_group_members(node)
                except LookupError:
                    continue
                if group_guid in members:
                    raise MembershipCycleError("nesting cycle detected")
                nxt.extend(m for m in members if m not in seen)
            frontier = nxt
            if not frontier:
                return

    async def add(self, group_guid: UUID, member_guid: UUID, expected_version: str | None = None) -> MembershipOutcome:
        """Add a member idempotently (present -> NO_OP).

        Args:
            group_guid: Target group GUID.
            member_guid: Member GUID.
            expected_version: Concurrency token checked against the group view.

        Returns:
            MembershipOutcome with same-DC verification.
        """
        group = await self._gateway.get_group(group_guid)
        if group is None:
            from mwa_ad_connector.domain.errors import TargetNotFoundError  # noqa: PLC0415

            raise TargetNotFoundError(f"target not found: {group_guid}")
        if expected_version is not None and expected_version != group.version_token:
            from mwa_ad_connector.domain.errors import ConcurrentModificationError  # noqa: PLC0415

            raise ConcurrentModificationError("group changed since expected_version")
        if member_guid in await self._gateway.list_group_members(group_guid):
            return MembershipOutcome("NO_OP", group_guid, member_guid, self._gateway.source_dc, verified=True)
        await self._cycle_check(group_guid, member_guid)
        await self._gateway.add_group_member(group_guid, member_guid)
        if member_guid not in await self._gateway.list_group_members(group_guid):
            raise VerificationFailedError("member not observed after add")
        return MembershipOutcome("APPLIED", group_guid, member_guid, self._gateway.source_dc, verified=True)

    async def remove(self, group_guid: UUID, member_guid: UUID) -> MembershipOutcome:
        """Remove a member idempotently (absent -> NO_OP).

        Args:
            group_guid: Target group GUID.
            member_guid: Member GUID.

        Returns:
            MembershipOutcome with same-DC verification.
        """
        if await self._gateway.get_group(group_guid) is None:
            from mwa_ad_connector.domain.errors import TargetNotFoundError  # noqa: PLC0415

            raise TargetNotFoundError(f"target not found: {group_guid}")
        if member_guid not in await self._gateway.list_group_members(group_guid):
            return MembershipOutcome("NO_OP", group_guid, member_guid, self._gateway.source_dc, verified=True)
        await self._gateway.remove_group_member(group_guid, member_guid)
        if member_guid in await self._gateway.list_group_members(group_guid):
            raise VerificationFailedError("member still observed after remove")
        return MembershipOutcome("APPLIED", group_guid, member_guid, self._gateway.source_dc, verified=True)
