"""Discovery service (RootDSE / capabilities via gateway)."""

from __future__ import annotations

from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.infrastructure.ldap.controls import PAGED_RESULTS_OID
from mwa_ad_connector.infrastructure.ldap.discovery import DomainCapabilities, RootDse


class DiscoveryService:
    """Expose discovery reads through the canonical DirectoryGateway.

    Args:
        gateway: Canonical directory gateway.
    """

    def __init__(self, gateway: DirectoryGateway) -> None:
        self._gateway = gateway

    async def get_rootdse(self, domain_id: str) -> RootDse:
        """Return the RootDSE view.

        Args:
            domain_id: Domain identifier.

        Returns:
            Parsed :class:`RootDse`.
        """
        raw = await self._gateway.get_rootdse(domain_id)

        def _list(key: str) -> list[str]:
            value = raw.get(key, [])
            return [str(v) for v in value] if isinstance(value, list) else [str(value)]

        def _one(key: str) -> str:
            values = _list(key)
            return values[0] if values else ""

        from datetime import UTC, datetime  # noqa: PLC0415

        _ = datetime.now(UTC)
        return RootDse(
            naming_contexts=_list("namingContexts") or _list("naming_contexts"),
            default_naming_context=_one("defaultNamingContext") or _one("default_naming_context"),
            dns_hostname="***REDACTED***",
            forest_functionality=_one("forestFunctionality") or _one("forest_functionality"),
            domain_functionality=_one("domainFunctionality") or _one("domain_functionality"),
            supported_controls=_list("supportedControl") or _list("supported_controls"),
            supported_capabilities=_list("supportedCapabilities") or _list("supported_capabilities"),
            source_dc=str(raw.get("sourceDc", raw.get("source_dc", self._gateway.source_dc))),
        )

    async def get_capabilities(self, domain_id: str) -> DomainCapabilities:
        """Return observed capability comparison.

        Args:
            domain_id: Domain identifier.

        Returns:
            :class:`DomainCapabilities` with missing requirements listed.
        """
        root = await self.get_rootdse(domain_id)
        paging = PAGED_RESULTS_OID in root.supported_controls
        ldaps = bool(getattr(self._gateway, "is_secure_transport", True))
        functional_ok = bool(root.default_naming_context)
        missing: list[str] = []
        if not paging:
            missing.append("paging")
        if not ldaps:
            missing.append("ldaps")
        if not functional_ok:
            missing.append("functional-level")

        from datetime import UTC, datetime  # noqa: PLC0415

        return DomainCapabilities(
            domain_id=domain_id,
            paging_supported=paging,
            ldaps_enforced=ldaps,
            functional_level_ok=functional_ok,
            missing=missing,
            source_dc=root.source_dc,
            checked_at=datetime.now(UTC),
        )
