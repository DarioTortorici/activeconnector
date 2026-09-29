"""Capability catalog (Sections 7.2-7.5).

Every executable capability is an allowlisted literal with static
metadata: risk level, required application scope and minimum AD ACL.
Unknown capabilities are rejected before any LDAP contact.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from mwa_ad_connector.domain.enums import RiskLevel

CapabilityId = Literal[
    "connector.health.read",
    "connector.readiness.read",
    "directory.rootdse.read",
    "directory.capabilities.read",
    "user.resolve",
    "group.resolve",
    "user.get",
    "group.get",
    "user.search",
    "group.search",
    "group.members.list",
    "group.member.add",
    "group.member.remove",
    "account.unlock",
    "account.password.reset",
    "account.password.force_change",
    "account.enable",
    "account.disable",
    "user.create",
    "user.attributes.update",
    "user.rename",
    "user.move",
    "user.delete",
    "group.create",
    "group.attributes.update",
    "group.rename",
    "group.move",
    "group.delete",
    "ou.create",
    "ou.rename",
    "ou.move",
    "ou.delete",
    "operation.get",
    "operation.list",
    "audit.get",
    "audit.export",
]


class CapabilityMetadata(BaseModel):
    """Static catalog entry for one capability.

    Attributes:
        capability: Stable capability identifier.
        risk: Risk classification driving approvals.
        scope: Application scope required on the caller context.
        min_acl: Minimum AD ACL the service account needs.
        description: Short human-readable purpose.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str = Field(min_length=1, max_length=64)
    risk: RiskLevel
    scope: str = Field(min_length=1, max_length=64)
    min_acl: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=512)


def _entry(
    capability: str,
    risk: RiskLevel,
    scope: str,
    min_acl: str,
    description: str,
) -> CapabilityMetadata:
    """Build a catalog entry without repeating field names at call sites.

    Args:
        capability: Stable capability identifier.
        risk: Risk classification.
        scope: Required application scope.
        min_acl: Minimum AD ACL description.
        description: Human-readable purpose.

    Returns:
        Populated capability metadata.
    """
    return CapabilityMetadata(capability=capability, risk=risk, scope=scope, min_acl=min_acl, description=description)


CATALOG: Final[dict[str, CapabilityMetadata]] = {
    "connector.health.read": _entry(
        "connector.health.read",
        RiskLevel.LOW,
        "ad.health.read",
        "No AD access beyond optional bind",
        "Local health probe.",
    ),
    "connector.readiness.read": _entry(
        "connector.readiness.read",
        RiskLevel.LOW,
        "ad.readiness.read",
        "Bind + RootDSE read",
        "Readiness probe incl. LDAP reachability.",
    ),
    "directory.rootdse.read": _entry(
        "directory.rootdse.read",
        RiskLevel.LOW,
        "ad.discovery.read",
        "Read RootDSE",
        "Domain discovery via RootDSE.",
    ),
    "directory.capabilities.read": _entry(
        "directory.capabilities.read",
        RiskLevel.LOW,
        "ad.discovery.read",
        "Read schema/config where permitted",
        "Compare configured vs observed features.",
    ),
    "user.resolve": _entry(
        "user.resolve",
        RiskLevel.LOW,
        "ad.user.read",
        "Read identifying attributes",
        "Resolve a user identifier to exactly one GUID.",
    ),
    "group.resolve": _entry(
        "group.resolve",
        RiskLevel.LOW,
        "ad.group.read",
        "Read identifying attributes",
        "Resolve a group identifier to exactly one GUID.",
    ),
    "user.get": _entry(
        "user.get",
        RiskLevel.LOW,
        "ad.user.read",
        "Read requested attributes",
        "Read a typed user view by GUID.",
    ),
    "group.get": _entry(
        "group.get",
        RiskLevel.LOW,
        "ad.group.read",
        "Read requested attributes",
        "Read a typed group view by GUID.",
    ),
    "user.search": _entry(
        "user.search",
        RiskLevel.MEDIUM,
        "ad.user.read",
        "Read within OU/BaseDN",
        "Predefined-filter user search with paging.",
    ),
    "group.search": _entry(
        "group.search",
        RiskLevel.MEDIUM,
        "ad.group.read",
        "Read within OU/BaseDN",
        "Predefined-filter group search with paging.",
    ),
    "group.members.list": _entry(
        "group.members.list",
        RiskLevel.LOW,
        "ad.group.members.read",
        "Read member + minimum attributes",
        "List direct group members with paging.",
    ),
    "group.member.add": _entry(
        "group.member.add",
        RiskLevel.HIGH,
        "ad.group.member.write",
        "Write member on target group",
        "Add a member to a group (idempotent NO_OP if present).",
    ),
    "group.member.remove": _entry(
        "group.member.remove",
        RiskLevel.HIGH,
        "ad.group.member.write",
        "Write member on target group",
        "Remove a member from a group (idempotent NO_OP if absent).",
    ),
    "account.unlock": _entry(
        "account.unlock",
        RiskLevel.MEDIUM,
        "ad.account.unlock",
        "Write lockoutTime on target",
        "Clear an account lockout.",
    ),
    "account.password.reset": _entry(
        "account.password.reset",
        RiskLevel.CRITICAL,
        "ad.account.password.reset",
        "Extended/write for unicodePwd on target over LDAPS",
        "Reset a password over a protected channel only.",
    ),
    "account.password.force_change": _entry(
        "account.password.force_change",
        RiskLevel.HIGH,
        "ad.account.password.force_change",
        "Write pwdLastSet",
        "Force password change at next logon.",
    ),
    "account.enable": _entry(
        "account.enable",
        RiskLevel.HIGH,
        "ad.account.enable",
        "Write userAccountControl",
        "Enable an account.",
    ),
    "account.disable": _entry(
        "account.disable",
        RiskLevel.HIGH,
        "ad.account.disable",
        "Write userAccountControl",
        "Disable an account (reason + approval).",
    ),
    "user.create": _entry(
        "user.create",
        RiskLevel.HIGH,
        "ad.user.create",
        "Create child user in OU + attribute writes",
        "Create a user in a managed OU.",
    ),
    "user.attributes.update": _entry(
        "user.attributes.update",
        RiskLevel.HIGH,
        "ad.user.attributes.write",
        "Write delegated attributes only",
        "Update allowlisted user attributes via staged diff.",
    ),
    "user.rename": _entry(
        "user.rename",
        RiskLevel.HIGH,
        "ad.user.rename",
        "Validated ModifyDN write in scope",
        "Rename a user (GUID unchanged).",
    ),
    "user.move": _entry(
        "user.move",
        RiskLevel.HIGH,
        "ad.user.move",
        "Move/ModifyDN between allowed OUs",
        "Move a user between managed OUs.",
    ),
    "user.delete": _entry(
        "user.delete",
        RiskLevel.CRITICAL,
        "ad.user.delete",
        "Delete child on target",
        "Delete a user (prefer disable/stage).",
    ),
    "group.create": _entry(
        "group.create",
        RiskLevel.HIGH,
        "ad.group.create",
        "Create group in OU",
        "Create a group in a managed OU.",
    ),
    "group.attributes.update": _entry(
        "group.attributes.update",
        RiskLevel.HIGH,
        "ad.group.attributes.write",
        "Write delegated attributes only",
        "Update allowlisted group attributes.",
    ),
    "group.rename": _entry(
        "group.rename",
        RiskLevel.HIGH,
        "ad.group.rename",
        "ModifyDN in scope",
        "Rename a group (GUID unchanged).",
    ),
    "group.move": _entry(
        "group.move",
        RiskLevel.HIGH,
        "ad.group.move",
        "ModifyDN within managed scope",
        "Move a group between managed OUs.",
    ),
    "group.delete": _entry(
        "group.delete",
        RiskLevel.CRITICAL,
        "ad.group.delete",
        "Delete group",
        "Delete a non-privileged group.",
    ),
    "ou.create": _entry(
        "ou.create",
        RiskLevel.HIGH,
        "ad.ou.create",
        "Create child OU",
        "Create an OU under managed scope.",
    ),
    "ou.rename": _entry(
        "ou.rename",
        RiskLevel.HIGH,
        "ad.ou.rename",
        "ModifyDN on OU",
        "Rename an OU (GUID unchanged).",
    ),
    "ou.move": _entry(
        "ou.move",
        RiskLevel.CRITICAL,
        "ad.ou.move",
        "ModifyDN within managed areas",
        "Move an OU subtree (preflight required).",
    ),
    "ou.delete": _entry(
        "ou.delete",
        RiskLevel.CRITICAL,
        "ad.ou.delete",
        "Delete OU (empty + unprotected only)",
        "Delete an empty, non-protected OU.",
    ),
    "operation.get": _entry(
        "operation.get",
        RiskLevel.LOW,
        "ad.operation.read",
        "No AD access",
        "Read operation state and redacted evidence.",
    ),
    "operation.list": _entry(
        "operation.list",
        RiskLevel.MEDIUM,
        "ad.operation.read",
        "No AD access",
        "List operations with allowlisted filters.",
    ),
    "audit.get": _entry(
        "audit.get",
        RiskLevel.HIGH,
        "ad.audit.read",
        "No AD access",
        "Read a redacted audit record.",
    ),
    "audit.export": _entry(
        "audit.export",
        RiskLevel.HIGH,
        "ad.audit.export",
        "No AD access",
        "Signed, bounded audit export.",
    ),
}

_READ_ONLY_SUFFIXES: Final[tuple[str, ...]] = (".read", ".resolve", ".get", ".list", ":resolve", ":search", ":list")


def is_known_capability(capability: str) -> bool:
    """Check whether a capability is in the allowlist catalog.

    Args:
        capability: Candidate capability identifier.

    Returns:
        True when present in CATALOG.
    """
    return capability in CATALOG


def is_mutation_capability(capability: str) -> bool:
    """Check whether a capability mutates directory or durable state.

    Heuristic: read/resolve/get/list/search capabilities are read-only;
    everything else in the catalog is a mutation (including audit export,
    which creates a signed export artifact).

    Args:
        capability: Catalog capability identifier.

    Returns:
        True for mutating capabilities.
    """
    for suffix in _READ_ONLY_SUFFIXES:
        if capability.endswith(suffix):
            return False
    return capability not in {"user.search", "group.search", "operation.list"}


def get_metadata(capability: str) -> CapabilityMetadata:
    """Fetch catalog metadata for a known capability.

    Args:
        capability: Catalog capability identifier.

    Returns:
        Metadata entry.

    Raises:
        KeyError: When the capability is not allowlisted.
    """
    return CATALOG[capability]
