"""Tenant/connector binding helpers (Step 8).

Re-export of the binding checks from :mod:`mwa_ad_connector.security.authorization`
so envelope and dependency layers import from a stable location.
"""

from __future__ import annotations

from mwa_ad_connector.security.authorization import (
    ConnectorMismatch,
    TenantMismatch,
    check_connector_binding,
    check_tenant_binding,
)

__all__ = [
    "ConnectorMismatch",
    "TenantMismatch",
    "check_connector_binding",
    "check_tenant_binding",
]
