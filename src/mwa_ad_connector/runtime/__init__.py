"""Runtime package: adapters, callbacks, reads, health and the API facade."""

from mwa_ad_connector.runtime.adapters import (
    AuditSinkAdapter,
    Clock,
    OperationRepositoryAdapter,
    SystemClock,
    caller_to_domain,
)
from mwa_ad_connector.runtime.api_service import ApiOperationService
from mwa_ad_connector.runtime.errors import OutOfScopeError, coerce_infrastructure_fault, deny_to_error

__all__ = [
    "ApiOperationService",
    "AuditSinkAdapter",
    "Clock",
    "OperationRepositoryAdapter",
    "OutOfScopeError",
    "SystemClock",
    "caller_to_domain",
    "coerce_infrastructure_fault",
    "deny_to_error",
]
