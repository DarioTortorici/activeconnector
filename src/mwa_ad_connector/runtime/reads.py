"""Read-capability dispatch over the canonical gateway (exact API response shapes)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from mwa_ad_connector.application.services.discovery_service import DiscoveryService
from mwa_ad_connector.application.services.identity_resolution_service import IdentityResolutionService
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.domain.capabilities import CATALOG
from mwa_ad_connector.domain.enums import IdentifierType, ObjectType
from mwa_ad_connector.domain.errors import RequestInvalidError, TargetNotFoundError
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.runtime.adapters import Clock

_MAX_PAGE_SIZE = 1000
_DEFAULT_PAGE_SIZE = 50


def _search_query(parameters: Mapping[str, Any]) -> str:
    """Build the gateway query string from the query profile and parameters."""
    profile = str(parameters.get("query_profile") or "")
    values = parameters.get("parameters")
    if isinstance(values, Mapping):
        for key in ("name", "query", "value"):
            candidate = values.get(key)
            if candidate:
                return str(candidate)
        for candidate in values.values():
            if candidate:
                return str(candidate)
    return str(parameters.get("query") or "") or profile


def _project(attributes: Mapping[str, Any], projection: Any) -> dict[str, Any]:  # noqa: ANN401 - request-supplied.
    """Apply an allowlisted attribute projection (case-insensitive)."""
    if not isinstance(projection, (list, tuple)) or not projection:
        return {str(key): value for key, value in attributes.items()}
    wanted = {str(name).lower() for name in projection}
    return {str(key): value for key, value in attributes.items() if str(key).lower() in wanted}


class ReadDispatcher:
    """Dispatch read capabilities, returning exact response-model dicts.

    Args:
        settings: Connector settings (defaults for missing target boundaries).
        gateway: Canonical directory gateway.
        clock: Clock used for observation timestamps.
    """

    def __init__(self, settings: ConnectorSettings, gateway: Any, clock: Clock) -> None:  # noqa: ANN401 - gateway duck-typed.
        self._settings = settings
        self._gateway = gateway
        self._clock = clock
        self._identity = IdentityResolutionService(gateway, domain_id=settings.domain_id, forest_id=settings.forest_id)
        self._discovery = DiscoveryService(gateway)

    def reference(
        self,
        target: Mapping[str, Any],
        default_type: ObjectType,
        *,
        placeholder: bool = False,
    ) -> ObjectReference:
        """Build an ObjectReference from an API target mapping.

        Args:
            target: Target mapping from the route.
            default_type: Object type when the target omits it.
            placeholder: Allow a deterministic placeholder GUID (creates).

        Returns:
            Validated object reference.

        Raises:
            RequestInvalidError: On invalid object/identifier types or shapes.
        """
        raw_type = str(target.get("object_type") or default_type.value).upper()
        try:
            object_type = ObjectType(raw_type)
        except ValueError as exc:
            raise RequestInvalidError(f"object_type not allowlisted: {raw_type}") from exc
        guid = self._parse_guid(target.get("object_guid")) if target.get("object_guid") else None
        kind: IdentifierType | None = None
        if target.get("identifier_type"):
            try:
                kind = IdentifierType(str(target["identifier_type"]).upper())
            except ValueError as exc:
                raise RequestInvalidError("identifier_type not allowlisted") from exc
        value = target.get("identifier_value")
        if guid is None and kind is None and placeholder:
            guid = UUID(int=0)
        try:
            return ObjectReference(
                object_type=object_type,
                object_guid=guid,
                identifier_type=kind,
                identifier_value=str(value) if value else None,
                domain_id=str(target.get("domain_id") or self._settings.domain_id),
                forest_id=str(target.get("forest_id") or self._settings.forest_id),
            )
        except ValueError as exc:
            raise RequestInvalidError(str(exc)) from exc

    @staticmethod
    def _parse_guid(raw: Any) -> UUID:  # noqa: ANN401 - request-supplied value.
        """Parse a GUID string or fail with a request error."""
        try:
            return UUID(str(raw))
        except ValueError as exc:
            raise RequestInvalidError("object_guid is not a valid UUID") from exc

    def require_guid(self, target: Mapping[str, Any]) -> UUID:
        """Return the target GUID or fail with a request error."""
        raw = target.get("object_guid")
        if not raw:
            raise RequestInvalidError("object_guid is required")
        return self._parse_guid(raw)

    async def _dn_for(self, ref: ObjectReference) -> str | None:
        """Resolve the current DN for a GUID-backed reference."""
        if ref.object_guid is None:
            return None
        if ref.object_type == ObjectType.USER:
            user = await self._gateway.get_user(ref.object_guid)
            return user.distinguished_name if user else None
        if ref.object_type == ObjectType.GROUP:
            group = await self._gateway.get_group(ref.object_guid)
            return group.distinguished_name if group else None
        ou = await self._gateway.get_ou(ref.object_guid)
        return ou.distinguished_name if ou else None

    async def dispatch(  # noqa: PLR0911 - flat capability dispatch stays readable.
        self, capability: str, target: Mapping[str, Any], parameters: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Execute one read capability.

        Args:
            capability: Allowlisted read capability.
            target: Route target mapping.
            parameters: Route parameters mapping.

        Returns:
            Response-model-shaped dict.

        Raises:
            RequestInvalidError: For unsupported read capabilities.
        """
        if capability == "directory.rootdse.read":
            return await self._rootdse(target)
        if capability == "directory.capabilities.read":
            return await self._capabilities(target)
        if capability in ("user.resolve", "group.resolve"):
            return await self._resolve(capability, target)
        if capability in ("user.get", "group.get"):
            return await self._get(capability, target, parameters)
        if capability in ("user.search", "group.search"):
            return await self._search(capability, target, parameters)
        if capability == "group.members.list":
            return await self._members(target, parameters)
        if capability in ("connector.health.read", "connector.readiness.read"):
            return {"status": "HEALTHY", "connector_id": self._settings.connector_id, "observed_at": self._clock.now()}
        raise RequestInvalidError(f"unsupported read capability: {capability}")

    async def _rootdse(self, target: Mapping[str, Any]) -> dict[str, Any]:
        """Read the redacted RootDSE view."""
        domain_id = str(target.get("domain_id") or self._settings.domain_id)
        root = await self._discovery.get_rootdse(domain_id)
        return {
            "domain_id": domain_id,
            "forest_id": self._settings.forest_id,
            "naming_contexts": list(root.naming_contexts),
            "functional_level": root.domain_functionality or root.forest_functionality or None,
            "observed_at": self._clock.now(),
        }

    async def _capabilities(self, target: Mapping[str, Any]) -> dict[str, Any]:
        """Read the observed capability comparison for one domain."""
        domain_id = str(target.get("domain_id") or self._settings.domain_id)
        await self._discovery.get_capabilities(domain_id)
        return {"domain_id": domain_id, "capabilities": sorted(CATALOG), "observed_at": self._clock.now()}

    async def _resolve(self, capability: str, target: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve exactly one identifier to a GUID-backed reference."""
        default = ObjectType.USER if capability == "user.resolve" else ObjectType.GROUP
        ref = self.reference(target, default)
        resolved = await self._identity.resolve(ref)
        if resolved.object_guid is None:
            raise TargetNotFoundError("resolution did not yield a stable GUID")
        dn = resolved.expected_dn or await self._dn_for(resolved)
        if not dn:
            raise TargetNotFoundError("resolution did not yield a distinguished name")
        return {
            "object_type": str(resolved.object_type),
            "object_guid": str(resolved.object_guid),
            "distinguished_name": dn,
            "domain_id": resolved.domain_id or self._settings.domain_id,
        }

    async def _get(self, capability: str, target: Mapping[str, Any], parameters: Mapping[str, Any]) -> dict[str, Any]:
        """Read one typed object by GUID with an allowlisted projection."""
        guid = self.require_guid(target)
        projection = parameters.get("projection")
        if capability == "user.get":
            user = await self._gateway.get_user(guid)
            if user is None:
                raise TargetNotFoundError(f"target not found: {guid}")
            return {
                "object_type": str(ObjectType.USER),
                "object_guid": str(user.object_guid),
                "distinguished_name": user.distinguished_name,
                "domain_id": user.domain_id,
                "display_name": user.display_name,
                "attributes": _project(user.attributes, projection),
                "version_token": user.version_token,
                "observed_at": user.observed_at,
            }
        group = await self._gateway.get_group(guid)
        if group is None:
            raise TargetNotFoundError(f"target not found: {guid}")
        attrs = {"name": group.name, "scope": group.group_scope, "category": group.group_category}
        return {
            "object_type": str(ObjectType.GROUP),
            "object_guid": str(group.object_guid),
            "distinguished_name": group.distinguished_name,
            "domain_id": group.domain_id,
            "display_name": group.name,
            "attributes": _project(attrs, projection),
            "version_token": group.version_token,
            "observed_at": group.observed_at,
        }

    async def _search(
        self, capability: str, target: Mapping[str, Any], parameters: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Run a query-profile search with opaque offset paging."""
        page_size = _page_size(parameters)
        offset = _offset(parameters)
        query = _search_query(parameters)
        page_token = str(offset) if offset > 0 else None
        if capability == "user.search":
            users, next_token = await self._gateway.search_users(query, page_size, page_token)
            items = [
                {
                    "object_type": str(ObjectType.USER),
                    "object_guid": str(user.object_guid),
                    "distinguished_name": user.distinguished_name,
                    "domain_id": user.domain_id,
                    "display_name": user.display_name,
                    "attributes": dict(user.attributes),
                    "version_token": user.version_token,
                    "observed_at": user.observed_at,
                }
                for user in users
            ]
        else:
            groups, next_token = await self._gateway.search_groups(query, page_size, page_token)
            items = [
                {
                    "object_type": str(ObjectType.GROUP),
                    "object_guid": str(group.object_guid),
                    "distinguished_name": group.distinguished_name,
                    "domain_id": group.domain_id,
                    "display_name": group.name,
                    "attributes": {"name": group.name, "scope": group.group_scope, "category": group.group_category},
                    "version_token": group.version_token,
                    "observed_at": group.observed_at,
                }
                for group in groups
            ]
        return {"items": items, "next_cursor": {"offset": int(next_token)} if next_token else None}

    async def _members(self, target: Mapping[str, Any], parameters: Mapping[str, Any]) -> dict[str, Any]:
        """List direct group members with offset paging and unresolved accounting."""
        group_guid = self.require_guid(target)
        member_guids = await self._gateway.list_group_members(group_guid)
        page_size = _page_size(parameters)
        offset = _offset(parameters)
        chunk = member_guids[offset : offset + page_size]
        members: list[dict[str, Any]] = []
        unresolved = 0
        for member_guid in chunk:
            ref = await self._gateway.resolve_by_guid(member_guid)
            if ref is None or ref.object_guid is None:
                unresolved += 1
                continue
            dn = ref.expected_dn or await self._dn_for(ref)
            if not dn:
                unresolved += 1
                continue
            members.append(
                {
                    "object_type": str(ref.object_type),
                    "object_guid": str(ref.object_guid),
                    "distinguished_name": dn,
                    "domain_id": ref.domain_id or self._settings.domain_id,
                }
            )
        end = offset + page_size
        return {
            "members": members,
            "unresolved_count": unresolved,
            "next_cursor": {"offset": end} if end < len(member_guids) else None,
        }


def _page_size(parameters: Mapping[str, Any]) -> int:
    """Clamp the requested page size into the supported window."""
    try:
        requested = int(parameters.get("page_size") or _DEFAULT_PAGE_SIZE)
    except (TypeError, ValueError):
        requested = _DEFAULT_PAGE_SIZE
    return max(1, min(requested, _MAX_PAGE_SIZE))


def _offset(parameters: Mapping[str, Any]) -> int:
    """Extract the non-negative offset from the decoded cursor."""
    cursor = parameters.get("cursor")
    if not isinstance(cursor, Mapping):
        return 0
    try:
        return max(0, int(cursor.get("offset") or 0))
    except (TypeError, ValueError):
        return 0
