"""Authorization: scope checks and tenant/connector binding (Step 8).

Every check fails closed and prevents cross-tenant or cross-connector
reuse of a caller identity.
"""

from __future__ import annotations

from collections.abc import Collection

from mwa_ad_connector.security.authentication import CallerContext


class CallerForbidden(Exception):
    """Raised when the caller lacks a required scope."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "CALLER_FORBIDDEN"


class TenantMismatch(CallerForbidden):
    """Raised when the request tenant does not match the caller binding."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "TENANT_BINDING_MISMATCH"


class ConnectorMismatch(CallerForbidden):
    """Raised when the request connector does not match the caller binding."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "CONNECTOR_BINDING_MISMATCH"


def require_scope(caller: CallerContext, scope: str) -> None:
    """Require a single scope on the caller.

    Raises:
        CallerForbidden: When the scope is missing.
    """
    if scope not in caller.scopes:
        raise CallerForbidden(f"caller {caller.subject!r} lacks required scope {scope!r}")


def require_any_scope(caller: CallerContext, scopes: Collection[str]) -> None:
    """Require at least one of ``scopes`` on the caller.

    Raises:
        CallerForbidden: When none of the scopes is present.
    """
    wanted = list(scopes)
    if not any(scope in caller.scopes for scope in wanted):
        raise CallerForbidden(f"caller {caller.subject!r} lacks any of the required scopes {wanted!r}")


def check_tenant_binding(caller: CallerContext, tenant_id: str) -> None:
    """Ensure the request tenant matches the authenticated caller tenant.

    Raises:
        TenantMismatch: On any mismatch (prevents cross-tenant reuse).
    """
    if not tenant_id or caller.tenant_id != tenant_id:
        raise TenantMismatch("request tenant does not match the authenticated caller tenant")


def check_connector_binding(caller: CallerContext, connector_id: str) -> None:
    """Ensure the request connector matches the authenticated caller connector.

    Raises:
        ConnectorMismatch: On any mismatch (prevents cross-connector reuse).
    """
    if not connector_id or caller.connector_id != connector_id:
        raise ConnectorMismatch("request connector does not match the authenticated caller connector")
