"""Shared mutation planning types and parameter helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import UUID

from mwa_ad_connector.application.ports.directory_gateway import AttributeMap
from mwa_ad_connector.domain.errors import RequestInvalidError

USER_TARGETS = frozenset(
    {
        "account.unlock",
        "account.password.reset",
        "account.password.force_change",
        "account.enable",
        "account.disable",
        "user.attributes.update",
        "user.rename",
        "user.move",
        "user.delete",
    }
)
GROUP_TARGETS = frozenset(
    {
        "group.member.add",
        "group.member.remove",
        "group.attributes.update",
        "group.rename",
        "group.move",
        "group.delete",
    }
)
OU_TARGETS = frozenset({"ou.rename", "ou.move", "ou.delete"})
MOVE_TARGETS = frozenset({"user.move", "group.move", "ou.move"})
CREATES = frozenset({"user.create", "group.create", "ou.create"})
SECRET_PARAMETER_KEYS = frozenset({"new_password", "approval", "dry_run", "expected_version"})

_GROUP_SCOPE_BITS: dict[str, int] = {"GLOBAL": 0x00000002, "DOMAIN_LOCAL": 0x00000004, "UNIVERSAL": 0x00000008}
_SECURITY_BIT = 0x80000000
_UINT32 = 0x1_0000_0000


@dataclass(frozen=True)
class MutationPlan:
    """Preflight-relevant facts resolved before any write.

    Attributes:
        target_dn: DN the scope/protected checks run against.
        target_kind: Protected-target dispatch kind.
        target_attrs: Redacted attributes feeding protected-target checks.
        destination_dn: Destination DN for move capabilities, when applicable.
    """

    target_dn: str
    target_kind: Literal["user", "group", "ou"]
    target_attrs: dict[str, Any] = field(default_factory=dict)
    destination_dn: str | None = None


@dataclass
class OutcomeTracker:
    """Mutable holder capturing the service-level disposition for the result."""

    disposition: str | None = None


def required_str(parameters: Mapping[str, Any], key: str) -> str:
    """Return a required non-empty string parameter."""
    value = parameters.get(key)
    if value is None or not str(value).strip():
        raise RequestInvalidError(f"missing required parameter: {key}")
    return str(value)


def opt_str(value: Any) -> str | None:  # noqa: ANN401 - parameter values are caller-supplied.
    """Return a non-empty string value or None."""
    if value is None:
        return None
    text = str(value)
    return text if text else None


def uuid_param(parameters: Mapping[str, Any], key: str) -> UUID:
    """Parse a required UUID parameter."""
    raw = parameters.get(key)
    if raw is None or not str(raw).strip():
        raise RequestInvalidError(f"missing required parameter: {key}")
    try:
        return UUID(str(raw))
    except ValueError as exc:
        raise RequestInvalidError(f"invalid UUID parameter: {key}") from exc


def attributes_param(parameters: Mapping[str, Any]) -> AttributeMap:
    """Normalize the staged-diff attribute map."""
    raw = parameters.get("attributes")
    if not isinstance(raw, Mapping) or not raw:
        raise RequestInvalidError("attributes must be a non-empty mapping")
    normalized: AttributeMap = {}
    for key, value in raw.items():
        name = str(key)
        if isinstance(value, str):
            normalized[name] = value
        elif isinstance(value, (list, tuple)):
            normalized[name] = [str(item) for item in value]
        else:
            normalized[name] = str(value)
    return normalized


def destination_dn(capability: str, parameters: Mapping[str, Any]) -> str:
    """Return the destination DN for move capabilities."""
    if capability == "ou.move":
        return required_str(parameters, "destination_parent")
    return required_str(parameters, "destination_ou")


def group_type_value(scope: str, category: str) -> int:
    """Map API scope/category labels to the signed AD groupType bitmask.

    Args:
        scope: GLOBAL, DOMAIN_LOCAL or UNIVERSAL.
        category: SECURITY or DISTRIBUTION.

    Returns:
        Signed 32-bit groupType value.

    Raises:
        RequestInvalidError: On unknown scope or category labels.
    """
    bit = _GROUP_SCOPE_BITS.get(scope.upper())
    if bit is None:
        raise RequestInvalidError(f"unknown group scope: {scope}")
    if category.upper() not in ("SECURITY", "DISTRIBUTION"):
        raise RequestInvalidError(f"unknown group category: {category}")
    value = bit | (_SECURITY_BIT if category.upper() == "SECURITY" else 0)
    return value - _UINT32 if value & _SECURITY_BIT else value
