"""RootDSE discovery and capability probing."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from mwa_ad_connector.infrastructure.ldap.connection import LdapConnectionManager
from mwa_ad_connector.infrastructure.ldap.error_mapping import map_ldap_result


class RootDse(BaseModel):
    """Redacted RootDSE view.

    Attributes:
        naming_contexts: Naming contexts advertised.
        default_naming_context: Default NC for the domain.
        dns_hostname: Server DNS hostname (redacted in API responses).
        forest_functionality: Forest functional level.
        domain_functionality: Domain functional level.
        supported_controls: Advertised control OIDs.
        supported_capabilities: Advertised capability OIDs.
        source_dc: DC that answered.
    """

    model_config = {"frozen": True}

    naming_contexts: list[str] = Field(default_factory=list)
    default_naming_context: str = ""
    dns_hostname: str = ""
    forest_functionality: str = ""
    domain_functionality: str = ""
    supported_controls: list[str] = Field(default_factory=list)
    supported_capabilities: list[str] = Field(default_factory=list)
    source_dc: str = ""


class DomainCapabilities(BaseModel):
    """Observed vs required capability comparison.

    Attributes:
        domain_id: Domain identifier.
        paging_supported: Whether paged results are advertised.
        ldaps_enforced: Whether the transport enforces LDAPS.
        functional_level_ok: Whether functional levels meet the minimum.
        missing: Missing requirements.
        source_dc: DC that answered.
        checked_at: Check timestamp.
    """

    model_config = {"frozen": True}

    domain_id: str = ""
    paging_supported: bool = False
    ldaps_enforced: bool = False
    functional_level_ok: bool = False
    missing: list[str] = Field(default_factory=list)
    source_dc: str = ""
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


async def get_rootdse(manager: LdapConnectionManager, pinned_dc: str | None = None) -> RootDse:
    """Read the RootDSE from the pinned DC.

    Args:
        manager: Connection manager.
        pinned_dc: DC override.

    Returns:
        Redacted :class:`RootDse`.

    Raises:
        RuntimeError: If the LDAP search fails.
    """
    from typing import Any  # noqa: PLC0415

    from ldap3 import BASE  # noqa: PLC0415

    def _op(conn: Any) -> dict[str, object]:
        conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["*"])
        result_code = int(dict(conn.result).get("result", 80))
        if result_code != 0:
            mapped = map_ldap_result(result_code, str(dict(conn.result)), "rootdse")
            raise RuntimeError(f"{mapped.code}: {mapped.remediation}")
        entries = list(conn.entries)
        if not entries:
            return {}
        return {str(k): v for k, v in dict(entries[0].entry_attributes_as_dict).items()}

    raw, host = await manager.execute(_op, pinned_dc)

    def _get(name: str) -> list[str]:
        values = raw.get(name, [])
        if isinstance(values, list):
            return [str(v) for v in values]
        return [str(values)] if values else []

    def _one(name: str) -> str:
        values = _get(name)
        return values[0] if values else ""

    return RootDse(
        naming_contexts=_get("namingContexts"),
        default_naming_context=_one("defaultNamingContext"),
        dns_hostname=_one("dnsHostName"),
        forest_functionality=_one("forestFunctionality"),
        domain_functionality=_one("domainFunctionality"),
        supported_controls=_get("supportedControl"),
        supported_capabilities=_get("supportedCapabilities"),
        source_dc=host or manager.pinned_host,
    )


async def get_capabilities(
    manager: LdapConnectionManager, domain_id: str, pinned_dc: str | None = None
) -> DomainCapabilities:
    """Compare observed RootDSE features against MVP requirements.

    Args:
        manager: Connection manager.
        domain_id: Domain identifier.
        pinned_dc: DC override.

    Returns:
        :class:`DomainCapabilities` with missing requirements listed.
    """
    from mwa_ad_connector.infrastructure.ldap.controls import PAGED_RESULTS_OID  # noqa: PLC0415

    root = await get_rootdse(manager, pinned_dc)
    paging = PAGED_RESULTS_OID in root.supported_controls
    ldaps = manager.is_ldaps_enforced
    functional_ok = bool(root.default_naming_context)
    missing: list[str] = []
    if not paging:
        missing.append("paging")
    if not ldaps:
        missing.append("ldaps")
    if not functional_ok:
        missing.append("functional-level")
    return DomainCapabilities(
        domain_id=domain_id,
        paging_supported=paging,
        ldaps_enforced=ldaps,
        functional_level_ok=functional_ok,
        missing=missing,
        source_dc=root.source_dc,
        checked_at=datetime.now(UTC),
    )
