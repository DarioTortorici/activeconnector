"""Configuration profiles: domain / forest / connector boundaries."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class DomainProfile(BaseModel):
    """Per-domain scope profile.

    Attributes:
        domain_id: Domain boundary identifier.
        forest_id: Parent forest boundary.
        base_dn: Domain search/mutation root.
        managed_ous: Allowlisted OUs for mutations.
        netbios_name: NetBIOS name hint for sAMAccountName scoping.
        dns_name: DNS domain name.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    domain_id: str = Field(min_length=1, max_length=128)
    forest_id: str = Field(min_length=1, max_length=128)
    base_dn: str = Field(min_length=3, max_length=512)
    managed_ous: list[str] = Field(min_length=1)
    netbios_name: str | None = Field(default=None, max_length=64)
    dns_name: str | None = Field(default=None, max_length=256)


class ForestProfile(BaseModel):
    """Per-forest grouping of domain profiles.

    Attributes:
        forest_id: Forest boundary identifier.
        domains: Domain profiles belonging to the forest.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    forest_id: str = Field(min_length=1, max_length=128)
    domains: list[DomainProfile] = Field(min_length=1)


class ConnectorProfile(BaseModel):
    """Connector identity bound to one customer/tenant and its forests.

    Attributes:
        customer_id: Customer boundary.
        tenant_id: Tenant boundary.
        connector_id: Connector identity.
        forests: Forest profiles served by this connector.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    customer_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    connector_id: str = Field(min_length=1, max_length=128)
    forests: list[ForestProfile] = Field(min_length=1)

    def domain_ids(self) -> list[str]:
        """Return all domain ids served by this connector.

        Returns:
            Sorted domain identifiers.
        """
        ids = [domain.domain_id for forest in self.forests for domain in forest.domains]
        return sorted(ids)

    def find_domain(self, domain_id: str) -> DomainProfile | None:
        """Find a domain profile by id.

        Args:
            domain_id: Domain boundary to look up.

        Returns:
            Matching profile or None.
        """
        for forest in self.forests:
            for domain in forest.domains:
                if domain.domain_id == domain_id:
                    return domain
        return None
