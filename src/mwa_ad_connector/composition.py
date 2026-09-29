"""Composition root: wire the LDAP gateway, stores, policy and services.

``build_runtime`` is the single place where concrete adapters are chosen; the
API layer consumes the resulting ``ConnectorRuntime`` through dependency
overrides so unit/contract tests can inject fakes without any AD access.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mwa_ad_connector.application.services.operation_service import OperationService
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.infrastructure.ldap.adapter import LdapDirectoryGateway
from mwa_ad_connector.infrastructure.ldap.connection import LdapConnectionConfig, LdapConnectionManager
from mwa_ad_connector.infrastructure.persistence.audit_store import HashChainedAuditStore
from mwa_ad_connector.infrastructure.persistence.nonce_store import InMemoryNonceStore
from mwa_ad_connector.infrastructure.persistence.operation_store import SqliteOperationStore
from mwa_ad_connector.policy.engine import PolicyEngine
from mwa_ad_connector.policy.scopes import ScopeChecker, ScopeConfig
from mwa_ad_connector.runtime.adapters import (
    AuditSinkAdapter,
    Clock,
    OperationRepositoryAdapter,
    SystemClock,
)
from mwa_ad_connector.runtime.api_service import ApiOperationService


@dataclass
class ConnectorRuntime:
    """Fully wired connector runtime.

    Attributes:
        settings: Connector settings used to build the runtime.
        gateway: Directory gateway (real LDAP adapter or injected fake).
        operation_service: Canonical operation orchestrator.
        api_service: API OperationServicePort implementation.
        policy: Policy engine used for mutation preflight.
        repository: Operation repository adapter.
        audit_store: Raw hash-chained audit store.
        nonce_store: Anti-replay nonce store.
        clock: Clock used for request/evidence timestamps.
    """

    settings: ConnectorSettings
    gateway: Any
    operation_service: OperationService
    api_service: ApiOperationService
    policy: PolicyEngine
    repository: OperationRepositoryAdapter
    audit_store: Any
    nonce_store: Any
    clock: Clock

    async def ping(self) -> dict[str, Any]:
        """Check directory connectivity with a redacted result."""
        pinger = getattr(self.gateway, "ping", None)
        if not callable(pinger):
            return {"ok": True, "detail": "injected"}
        payload = await pinger()
        return dict(payload) if isinstance(payload, dict) else {"ok": True, "detail": "reachable"}

    def close(self) -> None:
        """Close every store that exposes a ``close`` method (best effort)."""
        for store in (self.repository.store, self.audit_store, self.nonce_store):
            closer = getattr(store, "close", None)
            if callable(closer):
                with suppress(Exception):
                    closer()


def _state_path(settings: ConnectorSettings, filename: str) -> str:
    """Resolve the SQLite path inside the configured state directory."""
    if settings.state_dir in ("", ":memory:"):
        return ":memory:"
    directory = Path(settings.state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    return str(directory / filename)


def _build_gateway(settings: ConnectorSettings, gateway: Any) -> Any:  # noqa: ANN401 - injected fake or real adapter.
    """Return the injected gateway or build the real LDAPS adapter."""
    if gateway is not None:
        return gateway
    config = LdapConnectionConfig(
        hosts=(settings.dc_host,),
        port=settings.dc_port,
        use_ssl=settings.use_ldaps,
        ca_bundle=settings.trust_store_path,
        bind_user=settings.bind_user or "",
        bind_password=settings.bind_password,
        connect_timeout=settings.ldap_connect_timeout_seconds,
        operation_timeout=settings.ldap_operation_timeout_seconds,
        pool_size=settings.ldap_pool_size,
        base_dn=settings.base_dn,
    )
    manager = LdapConnectionManager(config)
    return LdapDirectoryGateway(
        manager,
        base_dn=settings.base_dn,
        domain_id=settings.domain_id,
        forest_id=settings.forest_id,
    )


def _source_dc(gateway: Any) -> str:  # noqa: ANN401 - gateway duck-typed.
    """Return the pinned DC label for operation records."""
    return str(getattr(gateway, "source_dc", "") or "unknown")


def build_runtime(  # noqa: PLR0913 - explicit injection seams.
    settings: ConnectorSettings,
    *,
    gateway: Any | None = None,  # noqa: ANN401 - injected DirectoryGateway fake.
    operation_store: Any | None = None,  # noqa: ANN401 - raw operation store.
    audit_store: Any | None = None,  # noqa: ANN401 - raw audit store.
    nonce_store: Any | None = None,  # noqa: ANN401 - raw nonce store.
    clock: Clock | None = None,
) -> ConnectorRuntime:
    """Build the fully wired runtime.

    Args:
        settings: Validated connector settings.
        gateway: Optional injected DirectoryGateway (tests); built over LDAPS
            with a fail-closed trust store when omitted.
        operation_store: Optional raw operation store (e.g. in-memory SQLite).
        audit_store: Optional raw hash-chained audit store.
        nonce_store: Optional raw nonce store.
        clock: Optional clock override for deterministic tests.

    Returns:
        Wired ``ConnectorRuntime`` ready for ``create_app`` or direct calls.
    """
    resolved_clock = clock or SystemClock()
    resolved_gateway = _build_gateway(settings, gateway)
    raw_operation_store = (
        operation_store
        if operation_store is not None
        else SqliteOperationStore(db_path=_state_path(settings, "operations.sqlite3"))
    )
    raw_audit_store = (
        audit_store
        if audit_store is not None
        else HashChainedAuditStore(db_path=_state_path(settings, "audit.sqlite3"))
    )
    raw_nonce_store = nonce_store if nonce_store is not None else InMemoryNonceStore()

    repository = OperationRepositoryAdapter(raw_operation_store)
    audit_sink = AuditSinkAdapter(raw_audit_store)
    scope_checker = ScopeChecker(
        {
            settings.domain_id: ScopeConfig(
                domain_id=settings.domain_id,
                base_dn=settings.base_dn,
                managed_ous=list(settings.managed_ous),
            )
        }
    )
    policy = PolicyEngine(scope_checker)
    operation_service = OperationService(repository, audit_sink, policy=None, source_dc=_source_dc(resolved_gateway))
    api_service = ApiOperationService(
        settings=settings,
        gateway=resolved_gateway,
        operation_service=operation_service,
        repository=repository,
        audit_store=raw_audit_store,
        policy=policy,
        scope_checker=scope_checker,
        clock=resolved_clock,
    )
    return ConnectorRuntime(
        settings=settings,
        gateway=resolved_gateway,
        operation_service=operation_service,
        api_service=api_service,
        policy=policy,
        repository=repository,
        audit_store=raw_audit_store,
        nonce_store=raw_nonce_store,
        clock=resolved_clock,
    )
