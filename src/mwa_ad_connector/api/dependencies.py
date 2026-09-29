"""FastAPI dependencies: settings, gateway, operation service, caller auth, headers.

Seam contract (Step 8/9/16): canonical modules (config.settings, security.*,
application.ports.*, application.services.*) are preferred when importable;
typed local fallbacks keep the API bootable and testable while those tracks
land in parallel. Dependency overrides in tests inject fakes for both ports.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Protocol

import jwt
from fastapi import Depends, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from mwa_ad_connector.api.error_handlers import ConnectorError

_CanonicalSettings: Any = None
_CanonicalConnectorSettings: Any = None
try:  # Canonical settings (Step 4 config track: Settings or ConnectorSettings).
    import mwa_ad_connector.config.settings as _config_settings_module
except ImportError:  # pragma: no cover - config track always present in practice.
    _config_settings_module = None  # type: ignore[assignment]
if _config_settings_module is not None:
    _CanonicalSettings = getattr(_config_settings_module, "Settings", None)
    _CanonicalConnectorSettings = getattr(_config_settings_module, "ConnectorSettings", None)

try:  # Canonical caller context (Step 8); fallback below.
    from mwa_ad_connector.security.authentication import CallerContext as _CanonicalCaller
except ImportError:  # pragma: no cover
    _CanonicalCaller = None  # type: ignore[assignment, misc]

try:  # Canonical gateway port (Step 2).
    from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway as _CanonicalGateway
except ImportError:  # pragma: no cover
    _CanonicalGateway = None  # type: ignore[assignment, misc]

try:  # Canonical operation service (Step 9+).
    from mwa_ad_connector.application.services.operation_service import OperationService as _CanonicalOpService
except ImportError:  # pragma: no cover
    _CanonicalOpService = None  # type: ignore[assignment, misc]


# ---------------------------------------------------------------------------
# Runtime configuration (typed, decoupled from the canonical Settings shape).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuntimeConfig:
    """Effective connector configuration used by the API layer."""

    connector_id: str = "connector-lab-01"
    tenant_id: str = "tenant-lab"
    customer_id: str = "customer-lab"
    environment: str = "lab"
    version: str = "0.1.0"
    api_host: str = "127.0.0.1"
    api_port: int = 8443
    payload_max_bytes: int = 1_048_576
    rate_limit_capacity: int = 100
    rate_limit_per_second: float = 10.0
    jwt_issuer: str = "mwa-trusted-agent"
    jwt_audience: str = "mwa-ad-connector"
    jwt_secret: str = "lab-only-change-me"  # noqa: S105 - lab default; production injects via MWA_CONNECTOR_JWT_SECRET.
    jwt_algorithms: tuple[str, ...] = ("HS256",)
    jwt_clock_skew_seconds: int = 60
    request_max_skew_seconds: int = 300
    page_token_secret: str = "lab-only-page-token-secret"  # noqa: S105 - lab default; see MWA_CONNECTOR_PAGE_TOKEN_SECRET.
    page_token_ttl_seconds: int = 300


_BEARER_TOKEN_PARTS = 2
_MAX_IDEMPOTENCY_KEY_LENGTH = 128


@lru_cache(maxsize=1)
def _load_runtime_config() -> RuntimeConfig:
    """Load RuntimeConfig from canonical settings when present, else defaults/env."""
    for candidate_cls in (_CanonicalSettings, _CanonicalConnectorSettings):
        if candidate_cls is None:
            continue
        try:
            canonical = candidate_cls()
            fields: dict[str, Any] = {}
            for name in RuntimeConfig.__dataclass_fields__:
                value = getattr(canonical, name, None)
                if value is not None:
                    fields[name] = value.get_secret_value() if isinstance(value, SecretStr) else value
            # Alternate config-track names mapped onto the runtime contract.
            if "payload_max_bytes" not in fields and getattr(canonical, "request_max_bytes", None) is not None:
                fields["payload_max_bytes"] = int(canonical.request_max_bytes)
            if "jwt_clock_skew_seconds" not in fields and getattr(canonical, "clock_skew_seconds", None) is not None:
                fields["jwt_clock_skew_seconds"] = int(canonical.clock_skew_seconds)
            return RuntimeConfig(**fields)
        except Exception:  # noqa: BLE001, S112 - fall through to safe defaults.
            continue

    def env(name: str, default: str) -> str:
        return os.environ.get(f"MWA_CONNECTOR_{name}", default)

    return RuntimeConfig(
        connector_id=env("CONNECTOR_ID", "connector-lab-01"),
        tenant_id=env("TENANT_ID", "tenant-lab"),
        customer_id=env("CUSTOMER_ID", "customer-lab"),
        environment=env("ENVIRONMENT", "lab"),
        jwt_issuer=env("JWT_ISSUER", "mwa-trusted-agent"),
        jwt_audience=env("JWT_AUDIENCE", "mwa-ad-connector"),
        jwt_secret=env("JWT_SECRET", "lab-only-change-me"),
        page_token_secret=env("PAGE_TOKEN_SECRET", "lab-only-page-token-secret"),
    )


def get_settings() -> RuntimeConfig:
    """Provide the effective runtime configuration (override in tests)."""
    return _load_runtime_config()


# Module-level Depends singletons (B008: FastAPI resolves these per request).
SettingsDep = Depends(get_settings)


# ---------------------------------------------------------------------------
# Caller context.
# ---------------------------------------------------------------------------


class CallerContextFallback(BaseModel):
    """Local caller identity mirroring the canonical CallerContext contract."""

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=256)
    issuer: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    customer_id: str = Field(default="", max_length=128)
    connector_id: str = Field(default="", max_length=128)
    scopes: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    certificate_thumbprint: str | None = None
    auth_method: str = "jwt-bearer"
    token_id: str | None = None
    authenticated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def _build_caller(**fields: Any) -> Any:
    """Instantiate the canonical CallerContext when available, else the fallback."""
    if _CanonicalCaller is not None:
        try:
            return _CanonicalCaller(**fields)
        except Exception:  # noqa: BLE001, S110 - fall back on shape mismatch.
            pass
    return CallerContextFallback(**fields)


def _parse_timestamp(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp header value, returning None when malformed."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


async def require_caller(
    request: Request,
    settings: RuntimeConfig = SettingsDep,
) -> Any:
    """Authenticate the caller (JWT) and enforce tenant/connector binding.

    Checks: Bearer JWT signature/expiry/issuer/audience, X-Tenant-ID match with
    the token tenant, X-Connector-ID match with local config, and (when the
    X-Request-Timestamp header is present) clock-skew window. Anti-replay nonce
    enforcement lives at the envelope/operation layer (nonce store).

    Raises:
        ConnectorError: 401 AUTHENTICATION_FAILED or 403 binding mismatch.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer ") or len(auth.split(" ", 1)) != _BEARER_TOKEN_PARTS:
        raise ConnectorError(
            code="AUTHENTICATION_FAILED",
            message="Missing or malformed Authorization Bearer token.",
            category="AUTHENTICATION",
            http_status=401,
        )
    raw_token = auth.split(" ", 1)[1].strip()
    try:
        claims = jwt.decode(
            raw_token,
            settings.jwt_secret,
            algorithms=list(settings.jwt_algorithms),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            leeway=settings.jwt_clock_skew_seconds,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise ConnectorError(
            code="AUTHENTICATION_FAILED",
            message="Caller token validation failed.",
            category="AUTHENTICATION",
            http_status=401,
            details={"reason": type(exc).__name__},
        ) from exc

    token_tenant = str(claims.get("tenant_id", ""))
    header_tenant = request.headers.get("X-Tenant-ID", "")
    if not header_tenant or header_tenant != token_tenant:
        raise ConnectorError(
            code="TENANT_BINDING_MISMATCH",
            message="X-Tenant-ID must match the caller token tenant.",
            category="AUTHORIZATION",
            http_status=403,
        )
    header_connector = request.headers.get("X-Connector-ID", "")
    if not header_connector or header_connector != settings.connector_id:
        raise ConnectorError(
            code="TENANT_BINDING_MISMATCH",
            message="X-Connector-ID must match this connector instance.",
            category="AUTHORIZATION",
            http_status=403,
        )

    timestamp_header = request.headers.get("X-Request-Timestamp")
    if timestamp_header:
        moment = _parse_timestamp(timestamp_header)
        now = datetime.now(UTC)
        if moment is None or abs((now - moment).total_seconds()) > settings.request_max_skew_seconds:
            raise ConnectorError(
                code="AUTHENTICATION_FAILED",
                message="X-Request-Timestamp outside the allowed skew window.",
                category="AUTHENTICATION",
                http_status=401,
            )

    scopes = claims.get("scopes", [])
    roles = claims.get("roles", [])
    return _build_caller(
        subject=str(claims.get("sub")),
        issuer=str(claims.get("iss")),
        audience=str(claims.get("aud")),
        tenant_id=token_tenant,
        customer_id=str(claims.get("customer_id", "")),
        connector_id=str(claims.get("connector_id", header_connector)),
        scopes=list(scopes) if isinstance(scopes, list) else [],
        roles=list(roles) if isinstance(roles, list) else [],
        certificate_thumbprint=request.headers.get("X-Client-Thumbprint"),
        auth_method="jwt-bearer",
        token_id=str(claims.get("jti")) if claims.get("jti") else None,
        authenticated_at=datetime.now(UTC),
    )


def require_scopes(*required: str) -> Callable[..., Awaitable[Any]]:
    """Build a dependency enforcing that the caller holds every given scope.

    Args:
        required: Scope names (e.g. "ad.user.read").

    Returns:
        FastAPI dependency returning the authenticated caller.
    """

    async def _check(caller: Any = RequireCallerDep) -> Any:  # noqa: ANN401
        held = set(getattr(caller, "scopes", None) or [])
        missing = [scope for scope in required if scope not in held]
        if missing:
            raise ConnectorError(
                code="CALLER_FORBIDDEN",
                message=f"Missing required scopes: {', '.join(missing)}.",
                category="AUTHORIZATION",
                http_status=403,
                details={"missing_scopes": ",".join(missing)},
            )
        return caller

    return _check


# Module-level caller singleton for scope-check composition.
RequireCallerDep = Depends(require_caller)


# ---------------------------------------------------------------------------
# Header helpers (idempotency, correlation, ticket).
# ---------------------------------------------------------------------------


async def get_correlation_id(request: Request) -> str:
    """Return the request correlation id (middleware-bound, header, or generated)."""
    state_id = getattr(request.state, "correlation_id", None)
    if isinstance(state_id, str) and state_id:
        return state_id
    header_id = request.headers.get("X-Correlation-ID")
    return header_id if header_id else "unknown"


async def get_idempotency_key(request: Request) -> str | None:
    """Return the Idempotency-Key header value within length bounds, else None."""
    value = request.headers.get("Idempotency-Key")
    if value is None or value == "":
        return None
    if len(value) > _MAX_IDEMPOTENCY_KEY_LENGTH:
        raise ConnectorError(
            code="REQUEST_INVALID",
            message=f"Idempotency-Key exceeds {_MAX_IDEMPOTENCY_KEY_LENGTH} characters.",
            category="VALIDATION",
            http_status=400,
        )
    return value


async def require_idempotency_key(request: Request) -> str:
    """Require the Idempotency-Key header for mutating endpoints."""
    value = await get_idempotency_key(request)
    if value is None:
        raise ConnectorError(
            code="REQUEST_INVALID",
            message="Idempotency-Key header is required for mutations.",
            category="VALIDATION",
            http_status=400,
            remediation="Send a unique Idempotency-Key per tenant+connector and retry.",
        )
    return value


async def get_ticket_id(request: Request) -> str | None:
    """Return the X-Ticket-ID header value, else None."""
    value = request.headers.get("X-Ticket-ID")
    return value if value else None


async def require_ticket_id(request: Request) -> str:
    """Require the X-Ticket-ID header for mutating endpoints."""
    value = await get_ticket_id(request)
    if value is None:
        raise ConnectorError(
            code="REQUEST_INVALID",
            message="X-Ticket-ID header is required for mutations.",
            category="VALIDATION",
            http_status=400,
        )
    return value


# ---------------------------------------------------------------------------
# Gateway + operation service ports (dependency-injected seams).
# ---------------------------------------------------------------------------


class DirectoryGatewayPort(Protocol):
    """Structural seam mirroring the canonical DirectoryGateway (Step 2)."""

    async def ping(self) -> dict[str, Any]:
        """Check LDAP reachability; returns redacted status dict."""
        ...  # pragma: no cover


class OperationServicePort(Protocol):
    """Structural seam for capability execution/lookup (Steps 9-15 services)."""

    async def execute_capability(  # noqa: PLR0913 - port signature mirrors the capability contract.
        self,
        *,
        capability: str,
        target: Mapping[str, Any],
        parameters: Mapping[str, Any],
        caller: Any,
        idempotency_key: str | None,
        correlation_id: str,
        ticket_id: str | None,
        dry_run: bool,
    ) -> dict[str, Any]:
        """Execute one capability synchronously; returns a result mapping."""
        ...  # pragma: no cover

    async def get_operation(self, operation_id: str, caller: Any) -> dict[str, Any] | None:  # noqa: ANN401
        """Fetch one operation record (redacted) or None when unknown."""
        ...  # pragma: no cover

    async def search_operations(
        self,
        filters: Mapping[str, str],
        page_size: int,
        page_token: str | None,
        caller: Any,  # noqa: ANN401
    ) -> dict[str, Any]:
        """Search operations by allowlisted filters; returns items/next_page_token."""
        ...  # pragma: no cover

    async def get_audit(self, audit_id: str, caller: Any) -> dict[str, Any] | None:  # noqa: ANN401
        """Fetch one audit record (redacted) or None when unknown."""
        ...  # pragma: no cover

    async def export_audit(self, params: Mapping[str, Any], caller: Any) -> dict[str, Any]:  # noqa: ANN401
        """Request a bounded tamper-evident audit export; returns a receipt."""
        ...  # pragma: no cover

    async def get_health(self) -> dict[str, Any]:
        """Return redacted liveness info for the health probe."""
        ...  # pragma: no cover

    async def get_readiness(self) -> dict[str, Any]:
        """Return readiness checks ({ready, checks:[{name,healthy,detail}]})."""
        ...  # pragma: no cover


async def get_gateway(settings: RuntimeConfig = SettingsDep) -> Any:
    """Provide the DirectoryGateway (canonical when configured).

    Raises:
        ConnectorError: 503 LDAP_UNAVAILABLE until the LDAP track wires the adapter.
    """
    _ = settings
    if _CanonicalGateway is not None:
        candidate = getattr(_CanonicalGateway, "default_instance", None)
        if callable(candidate):
            return candidate()
    raise ConnectorError(
        code="LDAP_UNAVAILABLE",
        message="Directory gateway is not configured on this instance.",
        category="DEPENDENCY",
        http_status=503,
        retryable=True,
    )


async def get_operation_service(settings: RuntimeConfig = SettingsDep) -> Any:
    """Provide the operation service (canonical when configured).

    Raises:
        ConnectorError: 503 until the application-services track wires it
            (hosts/tests inject a real implementation via dependency overrides).
    """
    _ = settings
    if _CanonicalOpService is not None:
        candidate = getattr(_CanonicalOpService, "default_instance", None)
        if callable(candidate):
            return candidate()
    raise ConnectorError(
        code="LDAP_UNAVAILABLE",
        message="Operation service is not configured on this instance.",
        category="DEPENDENCY",
        http_status=503,
        retryable=True,
    )


# ---------------------------------------------------------------------------
# Shared Depends singletons for route modules (B008-safe defaults).
# ---------------------------------------------------------------------------

GatewayDep = Depends(get_gateway)
OperationServiceDep = Depends(get_operation_service)
CorrelationIdDep = Depends(get_correlation_id)
IdempotencyKeyDep = Depends(require_idempotency_key)
TicketIdDep = Depends(require_ticket_id)
