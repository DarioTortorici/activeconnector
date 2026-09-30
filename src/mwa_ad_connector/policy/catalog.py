"""Allowlisted capability catalog (Step 7).

Every capability from plan section 7 is registered here with its risk
level, approval mode, required caller scopes, minimum AD ACL hint and
whether it mutates directory state. Unknown capabilities are denied by
default: :func:`get_entry` raises :class:`CapabilityNotAllowed`.

This module mirrors ``domain.enums.RiskLevel`` / ``ApprovalMode``
(owned by another agent); unify on those names when available.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(StrEnum):
    """Risk level attached to a capability (plan section 6.1)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalMode(StrEnum):
    """Approval mode attached to a capability (plan section 6.1)."""

    NONE = "NONE"
    REQUIRED = "REQUIRED"
    TWO_PERSON = "TWO_PERSON"
    BREAK_GLASS_FORBIDDEN = "BREAK_GLASS_FORBIDDEN"


class CapabilityNotAllowed(LookupError):
    """Raised when a capability is not present in the allowlist catalog."""

    def __init__(self, capability: str) -> None:
        super().__init__(f"capability not allowed: {capability!r}")
        self.capability = capability
        self.code = "CAPABILITY_NOT_ALLOWED"


class CapabilityEntry(BaseModel):
    """Static descriptor for a single allowlisted capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str
    risk: RiskLevel
    approval_mode: ApprovalMode
    scopes: list[str] = Field(min_length=1)
    min_acl_hint: str
    mutating: bool
    description: str = ""


def _entry(  # noqa: PLR0913 - catalog row builder keeps the table readable
    capability_id: str,
    risk: RiskLevel,
    approval: ApprovalMode,
    scopes: list[str],
    acl: str,
    mutating: bool,
    description: str = "",
) -> CapabilityEntry:
    """Build a catalog entry (short helper to keep the table readable)."""
    return CapabilityEntry(
        capability_id=capability_id,
        risk=risk,
        approval_mode=approval,
        scopes=scopes,
        min_acl_hint=acl,
        mutating=mutating,
        description=description,
    )


N = ApprovalMode.NONE
R = ApprovalMode.REQUIRED

CAPABILITY_CATALOG: dict[str, CapabilityEntry] = {
    # Release R0/R1: discovery and read (plan section 7.2, all non-mutating).
    "connector.health.read": _entry(
        "connector.health.read", RiskLevel.LOW, N, ["ad.health.read"], "none beyond minimum bind", False
    ),
    "connector.readiness.read": _entry(
        "connector.readiness.read", RiskLevel.LOW, N, ["ad.readiness.read"], "bind and RootDSE read", False
    ),
    "directory.rootdse.read": _entry(
        "directory.rootdse.read", RiskLevel.LOW, N, ["ad.discovery.read"], "read RootDSE", False
    ),
    "directory.capabilities.read": _entry(
        "directory.capabilities.read", RiskLevel.LOW, N, ["ad.discovery.read"], "read schema/config as permitted", False
    ),
    "user.resolve": _entry("user.resolve", RiskLevel.LOW, N, ["ad.user.read"], "read identifying attributes", False),
    "group.resolve": _entry("group.resolve", RiskLevel.LOW, N, ["ad.group.read"], "read identifying attributes", False),
    "user.get": _entry("user.get", RiskLevel.LOW, N, ["ad.user.read"], "read requested attributes", False),
    "group.get": _entry("group.get", RiskLevel.LOW, N, ["ad.group.read"], "read requested attributes", False),
    "user.search": _entry(
        "user.search",
        RiskLevel.MEDIUM,
        N,
        ["ad.user.search"],
        "read within OU/BaseDN",
        False,
        "predefined filters and paging only",
    ),
    "group.search": _entry(
        "group.search",
        RiskLevel.MEDIUM,
        N,
        ["ad.group.search"],
        "read within OU/BaseDN",
        False,
        "predefined filters and paging only",
    ),
    "group.members.list": _entry(
        "group.members.list", RiskLevel.LOW, N, ["ad.group.members.read"], "read member and minimum attributes", False
    ),
    # Release MVP: account and membership (plan section 7.3, all mutating).
    "group.member.add": _entry(
        "group.member.add",
        RiskLevel.HIGH,
        N,
        ["ad.group.member.write"],
        "write member on target group",
        True,
        "already present is NO_OP; cycle check required",
    ),
    "group.member.remove": _entry(
        "group.member.remove",
        RiskLevel.HIGH,
        N,
        ["ad.group.member.write"],
        "write member on target group",
        True,
        "absent member is NO_OP; minimum-membership policy applies",
    ),
    "account.unlock": _entry(
        "account.unlock",
        RiskLevel.MEDIUM,
        N,
        ["ad.account.unlock"],
        "write lockoutTime on target",
        True,
        "already unlocked is NO_OP",
    ),
    "account.password.reset": _entry(
        "account.password.reset",
        RiskLevel.CRITICAL,
        R,
        ["ad.account.password.reset"],
        "extended/write access for unicodePwd on target over LDAPS",
        True,
        "approval per policy; never compare passwords for idempotency",
    ),
    "account.password.force_change": _entry(
        "account.password.force_change",
        RiskLevel.HIGH,
        N,
        ["ad.account.password.force_change"],
        "write pwdLastSet",
        True,
        "idempotent on state",
    ),
    # Release GA: accounts, users, groups, OUs (plan section 7.4, all mutating).
    "account.enable": _entry(
        "account.enable",
        RiskLevel.HIGH,
        R,
        ["ad.account.state.write"],
        "write properties required for userAccountControl",
        True,
    ),
    "account.disable": _entry(
        "account.disable",
        RiskLevel.HIGH,
        R,
        ["ad.account.state.write"],
        "write userAccountControl",
        True,
        "reason required",
    ),
    "user.create": _entry(
        "user.create",
        RiskLevel.HIGH,
        N,
        ["ad.user.create"],
        "create child user in OU plus write of required attributes",
        True,
    ),
    "user.attributes.update": _entry(
        "user.attributes.update",
        RiskLevel.HIGH,
        N,
        ["ad.user.attributes.write"],
        "write of delegated attributes only",
        True,
        "staged diff enforced",
    ),
    "user.rename": _entry(
        "user.rename", RiskLevel.HIGH, N, ["ad.user.lifecycle.write"], "validated write/ModifyDN within scope", True
    ),
    "user.move": _entry(
        "user.move", RiskLevel.HIGH, N, ["ad.user.lifecycle.write"], "move/ModifyDN between permitted OUs", True
    ),
    "user.delete": _entry(
        "user.delete",
        RiskLevel.CRITICAL,
        R,
        ["ad.user.delete"],
        "delete child on target",
        True,
        "approval and reason; prefer disable/stage",
    ),
    "group.create": _entry("group.create", RiskLevel.HIGH, N, ["ad.group.create"], "create group in OU", True),
    "group.attributes.update": _entry(
        "group.attributes.update",
        RiskLevel.HIGH,
        N,
        ["ad.group.attributes.write"],
        "write of delegated attributes",
        True,
        "staged diff enforced",
    ),
    "group.rename": _entry("group.rename", RiskLevel.HIGH, N, ["ad.group.rename"], "ModifyDN", True),
    "group.move": _entry("group.move", RiskLevel.HIGH, N, ["ad.group.move"], "ModifyDN within scope", True),
    "group.delete": _entry(
        "group.delete",
        RiskLevel.CRITICAL,
        R,
        ["ad.group.delete"],
        "delete group",
        True,
        "non-privileged groups only; membership policy applies",
    ),
    "ou.create": _entry("ou.create", RiskLevel.HIGH, N, ["ad.ou.create"], "create child OU", True),
    "ou.rename": _entry("ou.rename", RiskLevel.HIGH, N, ["ad.ou.rename"], "ModifyDN on OU", True),
    "ou.move": _entry(
        "ou.move",
        RiskLevel.CRITICAL,
        N,
        ["ad.ou.move"],
        "ModifyDN within managed areas",
        True,
        "subtree preflight required",
    ),
    "ou.delete": _entry(
        "ou.delete", RiskLevel.CRITICAL, R, ["ad.ou.delete"], "delete OU", True, "empty and non-protected OU only"
    ),
    # Operations and audit (plan section 7.5, non-mutating).
    "operation.get": _entry(
        "operation.get", RiskLevel.LOW, N, ["ad.operation.read"], "same tenant/connector binding", False
    ),
    "operation.list": _entry(
        "operation.list",
        RiskLevel.MEDIUM,
        N,
        ["ad.operation.read"],
        "allowlisted filters and paging",
        False,
        "retention applies",
    ),
    "audit.get": _entry(
        "audit.get",
        RiskLevel.HIGH,
        N,
        ["ad.audit.read"],
        "compliance role",
        False,
        "redaction mandatory; access is audited",
    ),
    "audit.export": _entry(
        "audit.export",
        RiskLevel.HIGH,
        R,
        ["ad.audit.export"],
        "administrative approval",
        False,
        "signed/tamper-evident limited export",
    ),
}

ALL_CAPABILITIES: frozenset[str] = frozenset(CAPABILITY_CATALOG)


def get_entry(capability: str) -> CapabilityEntry:
    """Return the catalog entry for ``capability``.

    Raises:
        CapabilityNotAllowed: If the capability is not allowlisted (deny by default).
    """
    try:
        return CAPABILITY_CATALOG[capability]
    except KeyError as exc:
        raise CapabilityNotAllowed(capability) from exc


def is_known(capability: str) -> bool:
    """Return True when ``capability`` is present in the allowlist catalog."""
    return capability in CAPABILITY_CATALOG


def is_mutating(capability: str) -> bool:
    """Return True when the capability mutates directory state.

    Raises:
        CapabilityNotAllowed: If the capability is not allowlisted.
    """
    return get_entry(capability).mutating


def requires_approval(capability: str) -> bool:
    """Return True when the capability needs an approval context.

    Any mode other than ``NONE`` (``REQUIRED``, ``TWO_PERSON``,
    ``BREAK_GLASS_FORBIDDEN``) counts as requiring approval; the exact
    mode is enforced by :mod:`mwa_ad_connector.policy.approvals`.

    Raises:
        CapabilityNotAllowed: If the capability is not allowlisted.
    """
    return get_entry(capability).approval_mode is not ApprovalMode.NONE
