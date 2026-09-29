"""DN scope checks: Base DN containment, managed OUs, domain binding (Step 7).

A target DN is in scope when it sits inside the domain Base DN and, when
managed OUs are configured, inside at least one of them. Unknown domains
are out of scope (deny by default).
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping

from pydantic import BaseModel, ConfigDict


class ScopeConfig(BaseModel):
    """Scope configuration for a single managed domain."""

    model_config = ConfigDict(extra="forbid")

    domain_id: str
    base_dn: str
    managed_ous: list[str] = []


def normalize_dn(dn: str) -> str:
    """Normalize a DN for containment comparison.

    Lowercases, strips whitespace around RDN separators and keeps escaped
    commas (``\\\\,``) intact so ``is_dn_inside`` compares component-wise.
    """
    parts = _split_dn(dn)
    return ",".join(part.strip().lower() for part in parts if part.strip())


def _split_dn(dn: str) -> list[str]:
    """Split a DN on unescaped commas."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in dn:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def is_dn_inside(child_dn: str, base_dn: str) -> bool:
    """Return True when ``child_dn`` is inside (or equal to) ``base_dn``.

    Comparison is component-wise from the root, so ``OU=X,DC=a`` is not
    considered inside ``OU=X,DC=b`` and sibling subtrees never match.
    Empty inputs never match.
    """
    child = normalize_dn(child_dn)
    base = normalize_dn(base_dn)
    if not child or not base:
        return False
    child_parts = child.split(",")
    base_parts = base.split(",")
    if len(child_parts) < len(base_parts):
        return False
    return child_parts[len(child_parts) - len(base_parts) :] == base_parts


class ScopeChecker:
    """Check target DNs against configured domain scopes."""

    def __init__(self, configs: Mapping[str, ScopeConfig] | Iterable[ScopeConfig]) -> None:
        """Store scope configs keyed by domain id."""
        if isinstance(configs, Mapping):
            self._configs: dict[str, ScopeConfig] = dict(configs)
        else:
            self._configs = {config.domain_id: config for config in configs}

    @property
    def domain_ids(self) -> Collection[str]:
        """Return the configured domain ids."""
        return tuple(self._configs)

    def is_managed(self, domain_id: str, target_dn: str) -> bool:
        """Return True when the DN is managed (no reason to deny)."""
        return self.check(domain_id, target_dn) is None

    def check(self, domain_id: str, target_dn: str) -> str | None:
        """Return None when in scope, otherwise an explainable deny reason.

        Reasons cover unknown domain binding, targets outside the Base DN
        and targets outside every managed OU.
        """
        config = self._configs.get(domain_id)
        if config is None:
            return f"unknown domain binding: {domain_id!r} is not configured"
        if not target_dn or not target_dn.strip():
            return "empty target DN is out of scope"
        if not is_dn_inside(target_dn, config.base_dn):
            return f"target DN is outside Base DN {config.base_dn!r} of domain {domain_id!r}"
        if config.managed_ous and not any(is_dn_inside(target_dn, ou) for ou in config.managed_ous):
            return f"target DN is outside managed OUs of domain {domain_id!r}"
        return None
