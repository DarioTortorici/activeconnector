"""Deterministic identity resolution (GUID-first, allowlisted identifiers).

Uses the canonical :class:`DirectoryGateway` port and domain errors.
No heuristic "first match": zero matches raise ``TargetNotFoundError``,
multiple exact matches raise ``AmbiguousTargetError``.
"""

from __future__ import annotations

from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.domain.enums import IdentifierType, ObjectType
from mwa_ad_connector.domain.errors import AmbiguousTargetError, RequestInvalidError, TargetNotFoundError
from mwa_ad_connector.domain.identifiers import ObjectReference


class IdentityResolutionService:
    """Resolve ObjectReference to a single GUID-backed reference.

    Args:
        gateway: Canonical directory gateway (real adapter or fake).
        domain_id: Owning domain id for synthesized references.
        forest_id: Owning forest id for synthesized references.
    """

    def __init__(self, gateway: DirectoryGateway, domain_id: str = "", forest_id: str = "") -> None:
        self._gateway = gateway
        self._domain_id = domain_id
        self._forest_id = forest_id

    async def resolve(self, target: ObjectReference) -> ObjectReference:
        """Resolve a target reference to its stable GUID identity.

        Args:
            target: ObjectReference with object_guid or identifier pair.

        Returns:
            Canonical reference carrying the resolved object_guid.

        Raises:
            TargetNotFoundError: On zero matches.
            AmbiguousTargetError: On multiple exact matches.
            RequestInvalidError: On unsupported identifier kinds.
        """
        if target.object_guid is not None:
            resolved = await self._gateway.resolve_by_guid(target.object_guid)
            if resolved is None:
                raise TargetNotFoundError(f"target not found: {target.object_guid}")
            return resolved
        kind = target.identifier_type
        value = (target.identifier_value or "").strip()
        if kind is None or not value:
            raise RequestInvalidError("object_guid or identifier pair is required")
        if kind == IdentifierType.OBJECT_GUID:
            return await self.resolve(
                ObjectReference(
                    object_type=target.object_type,
                    object_guid=UUID(value),
                    domain_id=target.domain_id,
                    forest_id=target.forest_id,
                )
            )
        if kind == IdentifierType.DISTINGUISHED_NAME:
            return await self._resolve_by_dn(target, value)
        if kind in (IdentifierType.UPN, IdentifierType.SAM_ACCOUNT_NAME, IdentifierType.MAIL):
            return await self._resolve_user(target, kind, value)
        if kind == IdentifierType.GROUP_NAME:
            return await self._resolve_group(target, value)
        raise RequestInvalidError(f"identifier not allowlisted: {kind}")

    async def _resolve_by_dn(self, target: ObjectReference, dn: str) -> ObjectReference:
        lookup = getattr(self._gateway, "lookup_by_dn", None)
        if lookup is None:
            raise RequestInvalidError("DN resolution is not supported by this gateway; use object_guid")
        entry = await lookup(dn)
        if entry is None:
            raise TargetNotFoundError("target not found: dn lookup empty")
        attrs = entry.get("attributes", {})
        from mwa_ad_connector.infrastructure.ldap.mappings import guid_bytes_le_to_uuid  # noqa: PLC0415

        guid: UUID | None = None
        if isinstance(attrs, dict):
            raw = attrs.get("objectGUID")
            blob = raw[0] if isinstance(raw, list) and raw else raw
            if isinstance(blob, str):
                blob = blob.encode("latin1")
            if isinstance(blob, (bytes, bytearray)):
                guid = guid_bytes_le_to_uuid(bytes(blob))
        if guid is None:
            raise TargetNotFoundError("target not found: dn has no readable GUID")
        resolved = await self._gateway.resolve_by_guid(guid)
        if resolved is None:
            return ObjectReference(
                object_type=target.object_type,
                object_guid=guid,
                domain_id=target.domain_id,
                forest_id=target.forest_id,
                expected_dn=dn,
            )
        return resolved

    async def _resolve_user(self, target: ObjectReference, kind: IdentifierType, value: str) -> ObjectReference:
        users, _ = await self._gateway.search_users(value, 50)
        lowered = value.lower()
        if kind == IdentifierType.UPN:
            exact = [u for u in users if (u.user_principal_name or "").lower() == lowered]
        elif kind == IdentifierType.MAIL:
            exact = [u for u in users if str(u.attributes.get("mail", "")).lower() == lowered]
        else:
            exact = [u for u in users if u.sam_account_name.lower() == lowered]
        if not exact:
            raise TargetNotFoundError(f"target not found: {kind}")
        if len(exact) > 1:
            raise AmbiguousTargetError(f"ambiguous target: {len(exact)} matches for {kind}")
        user = exact[0]
        return ObjectReference(
            object_type=ObjectType.USER,
            object_guid=user.object_guid,
            domain_id=user.domain_id,
            forest_id=target.forest_id,
            expected_dn=user.distinguished_name,
        )

    async def _resolve_group(self, target: ObjectReference, value: str) -> ObjectReference:
        groups, _ = await self._gateway.search_groups(value, 50)
        lowered = value.lower()
        exact = [g for g in groups if g.sam_account_name.lower() == lowered or g.name.lower() == lowered]
        if not exact:
            raise TargetNotFoundError("target not found: GROUP_NAME")
        if len(exact) > 1:
            raise AmbiguousTargetError(f"ambiguous target: {len(exact)} matches for GROUP_NAME")
        group = exact[0]
        return ObjectReference(
            object_type=ObjectType.GROUP,
            object_guid=group.object_guid,
            domain_id=group.domain_id,
            forest_id=target.forest_id,
            expected_dn=group.distinguished_name,
        )

    async def require_guid(self, target: ObjectReference) -> UUID:
        """Resolve and return the stable GUID, requiring identifier success.

        Args:
            target: ObjectReference to resolve.

        Returns:
            Resolved object GUID.
        """
        resolved = await self.resolve(target)
        if resolved.object_guid is None:
            raise TargetNotFoundError("resolution did not yield a stable GUID")
        return resolved.object_guid

    async def refresh(self, guid: UUID) -> ObjectReference:
        """Re-resolve the current reference immediately before a mutation.

        Args:
            guid: Stable GUID.

        Returns:
            Fresh reference.

        Raises:
            TargetNotFoundError: If the object vanished.
        """
        resolved = await self._gateway.resolve_by_guid(guid)
        if resolved is None:
            raise TargetNotFoundError(f"target not found: {guid}")
        return resolved
