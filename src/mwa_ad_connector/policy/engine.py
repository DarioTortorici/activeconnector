"""Policy engine orchestrating catalog, scopes, protected targets, approvals (Step 7)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from mwa_ad_connector.policy.preflight import PreflightRequest, PreflightResult, preflight_request
from mwa_ad_connector.policy.scopes import ScopeChecker


class PolicyDecision(BaseModel):
    """ALLOW/DENY decision with an explainable code and reason."""

    model_config = ConfigDict(extra="forbid")

    decision: Literal["ALLOW", "DENY"]
    code: str
    reason: str
    capability: str


class PolicyEngine:
    """Orchestrate the preflight pipeline and render an ALLOW/DENY decision."""

    def __init__(self, scope_checker: ScopeChecker | None = None) -> None:
        """Bind the engine to domain scope configuration."""
        self._scope_checker = scope_checker

    @property
    def scope_checker(self) -> ScopeChecker | None:
        """Return the configured scope checker, if any."""
        return self._scope_checker

    def decide(self, request: PreflightRequest, *, now: datetime | None = None) -> PolicyDecision:
        """Evaluate ``request`` and return an explainable ALLOW/DENY decision."""
        result = self.evaluate(request, now=now)
        if result.allowed:
            return PolicyDecision(
                decision="ALLOW", code=result.code, reason=result.reason, capability=result.capability
            )
        return PolicyDecision(decision="DENY", code=result.code, reason=result.reason, capability=result.capability)

    def evaluate(self, request: PreflightRequest, *, now: datetime | None = None) -> PreflightResult:
        """Run the full preflight pipeline and return the raw result."""
        return preflight_request(request, scope_checker=self._scope_checker, now=now)
