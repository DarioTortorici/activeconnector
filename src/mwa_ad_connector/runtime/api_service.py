"""API operation-service facade: reads, mutations, operations and audit surfaces."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, timedelta
from typing import Any
from uuid import uuid4

from mwa_ad_connector.api.schemas.operations import OPERATION_SEARCH_FILTERS
from mwa_ad_connector.application.ports.directory_gateway import DirectoryGateway
from mwa_ad_connector.application.services.operation_service import OperationService
from mwa_ad_connector.config.settings import ConnectorSettings
from mwa_ad_connector.domain.capabilities import is_mutation_capability
from mwa_ad_connector.domain.enums import ObjectType
from mwa_ad_connector.domain.errors import DomainError, PolicyDeniedError, RequestInvalidError
from mwa_ad_connector.domain.operations import ApprovalContext as DomainApprovalContext
from mwa_ad_connector.domain.operations import CapabilityRequest, MutationResult
from mwa_ad_connector.policy.approvals import ApprovalContext as PolicyApprovalContext
from mwa_ad_connector.policy.catalog import CapabilityNotAllowed, get_entry
from mwa_ad_connector.policy.engine import PolicyEngine
from mwa_ad_connector.policy.preflight import PreflightRequest
from mwa_ad_connector.policy.scopes import ScopeChecker
from mwa_ad_connector.runtime.adapters import Clock, OperationRepositoryAdapter, caller_to_domain
from mwa_ad_connector.runtime.callbacks import MutationCallbacks
from mwa_ad_connector.runtime.envelope import parse_approval, parse_bound
from mwa_ad_connector.runtime.errors import coerce_infrastructure_fault, deny_to_error
from mwa_ad_connector.runtime.health import collect_readiness
from mwa_ad_connector.runtime.params import CREATES, OutcomeTracker
from mwa_ad_connector.runtime.reads import ReadDispatcher
from mwa_ad_connector.security.redaction import redact_dict

_READINESS_TIMEOUT_SECONDS = 5.0
_REQUEST_TTL_SECONDS = 300


class ApiOperationService:
    """Canonical OperationServicePort implementation over the wired runtime.

    Args:
        settings: Connector settings (kill switches, scope, timeouts).
        gateway: Canonical directory gateway.
        operation_service: Canonical orchestrator.
        repository: Operation repository adapter (raw store + record cache).
        audit_store: Raw hash-chained audit store.
        policy: Policy engine used for preflight evaluation.
        scope_checker: DN scope checker.
        clock: Clock used for request/evidence timestamps.
    """

    def __init__(  # noqa: PLR0913 - composition wires explicit dependencies.
        self,
        *,
        settings: ConnectorSettings,
        gateway: DirectoryGateway,
        operation_service: OperationService,
        repository: OperationRepositoryAdapter,
        audit_store: Any,  # noqa: ANN401 - raw store duck-typed.
        policy: PolicyEngine,
        scope_checker: ScopeChecker,
        clock: Clock,
    ) -> None:
        self._settings = settings
        self._gateway = gateway
        self._operations = operation_service
        self._repository = repository
        self._audit_store = audit_store
        self._policy = policy
        self._clock = clock
        self._reads = ReadDispatcher(settings, gateway, clock)
        self._callbacks = MutationCallbacks(gateway, settings, clock, scope_checker)

    async def execute_capability(  # noqa: PLR0913 - port signature mirrors the capability contract.
        self,
        *,
        capability: str,
        target: Mapping[str, Any],
        parameters: Mapping[str, Any],
        caller: Any,  # noqa: ANN401 - API caller model or mapping.
        idempotency_key: str | None,
        correlation_id: str,
        ticket_id: str | None,
        dry_run: bool,
    ) -> dict[str, Any]:
        """Execute one capability synchronously over the wired runtime."""
        if capability == "connector.health.read":
            return await self.get_health()
        if capability == "connector.readiness.read":
            return await self.get_readiness()
        if is_mutation_capability(capability):
            return await self._execute_mutation(
                capability=capability,
                target=dict(target),
                parameters=dict(parameters),
                caller=caller,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
                ticket_id=ticket_id,
                dry_run=dry_run,
            )
        return await self._reads.dispatch(capability, dict(target), dict(parameters))

    async def _execute_mutation(  # noqa: PLR0913 - explicit execution dimensions.
        self,
        *,
        capability: str,
        target: Mapping[str, Any],
        parameters: Mapping[str, Any],
        caller: Any,  # noqa: ANN401 - API caller model or mapping.
        idempotency_key: str | None,
        correlation_id: str,
        ticket_id: str | None,
        dry_run: bool,
    ) -> dict[str, Any]:
        """Preflight and execute one mutating capability."""
        try:
            get_entry(capability)
        except CapabilityNotAllowed as exc:
            raise PolicyDeniedError(str(exc)) from exc
        if not self._settings.enable_mutations:
            raise PolicyDeniedError("mutations are disabled by configuration")
        if capability == "account.password.reset" and not self._settings.enable_password_reset:
            raise PolicyDeniedError("password reset is disabled by configuration")
        self._callbacks.validate(capability, parameters)
        domain_caller = caller_to_domain(caller, self._settings, now=self._clock.now())
        ref = self._target_reference(capability, target)
        plan = await self._callbacks.plan(capability, ref, parameters)
        effective_dry_run = True if self._settings.validation_mode_only else dry_run
        approval_values = parse_approval(parameters)
        policy_approval = (
            PolicyApprovalContext(**approval_values, capability=capability) if approval_values is not None else None
        )
        decision = self._policy.evaluate(
            PreflightRequest(
                capability=capability,
                domain_id=ref.domain_id,
                target_dn=plan.target_dn,
                target_kind=plan.target_kind,
                target_attrs=plan.target_attrs,
                approval=policy_approval,
                dry_run=effective_dry_run,
                caller_scopes=list(domain_caller.scopes),
            )
        )
        if not decision.allowed:
            raise deny_to_error(decision.code, decision.reason)
        tracker = OutcomeTracker()
        mutate, verify = self._callbacks.build(capability, ref, parameters, tracker)
        request = self._build_request(
            capability=capability,
            ref=ref,
            parameters=parameters,
            caller=domain_caller,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            ticket_id=ticket_id,
            dry_run=effective_dry_run,
            approval_values=approval_values,
        )
        try:
            result = await self._operations.execute(request, domain_caller, mutate, verify)
        except DomainError:
            raise
        except Exception as exc:  # noqa: BLE001 - mapped to stable domain errors.
            raise coerce_infrastructure_fault(exc) from exc
        data = self._result_dict(result)
        if tracker.disposition == "NO_OP" and data["state"] == "AD_VERIFIED":
            data["disposition"] = "NO_OP"
        return data

    def _target_reference(self, capability: str, target: Mapping[str, Any]) -> Any:  # noqa: ANN401 - ObjectReference.
        """Build the target reference, using a placeholder GUID for creates."""
        if capability.startswith("group"):
            default = ObjectType.GROUP
        elif capability.startswith("ou"):
            default = ObjectType.OU
        else:
            default = ObjectType.USER
        return self._reads.reference(target, default, placeholder=capability in CREATES)

    def _build_request(  # noqa: PLR0913 - explicit envelope dimensions.
        self,
        *,
        capability: str,
        ref: Any,  # noqa: ANN401 - ObjectReference.
        parameters: Mapping[str, Any],
        caller: Any,  # noqa: ANN401 - domain caller context.
        idempotency_key: str | None,
        correlation_id: str,
        ticket_id: str | None,
        dry_run: bool,
        approval_values: Mapping[str, Any] | None,
    ) -> CapabilityRequest:
        """Build the canonical capability request from API inputs."""
        now = self._clock.now()
        domain_approval = DomainApprovalContext(**approval_values) if approval_values is not None else None
        try:
            return CapabilityRequest(
                capability=capability,
                customer_id=caller.customer_id,
                tenant_id=caller.tenant_id,
                connector_id=caller.connector_id,
                forest_id=ref.forest_id,
                domain_id=ref.domain_id,
                target=ref,
                parameters=self._callbacks.request_parameters(parameters),
                dry_run=dry_run,
                idempotency_key=idempotency_key or None,
                correlation_id=correlation_id or "unknown",
                ticket_id=ticket_id or None,
                requested_at=now,
                expires_at=now + timedelta(seconds=_REQUEST_TTL_SECONDS),
                nonce=uuid4().hex,
                approval_context=domain_approval,
                expected_version=parameters.get("expected_version"),
                requested_by=caller.subject,
            )
        except ValueError as exc:
            raise RequestInvalidError(f"capability request is invalid: {exc}") from exc

    @staticmethod
    def _result_dict(result: MutationResult) -> dict[str, Any]:
        """Convert a domain MutationResult to the route-facing dict (no secrets)."""
        evidence = result.verification_evidence.model_dump(mode="json") if result.verification_evidence else None
        hint = result.entra_evidence_hint.model_dump(mode="json") if result.entra_evidence_hint else None
        return {
            "operation_id": result.operation_id,
            "state": str(result.state),
            "disposition": str(result.disposition),
            "target_object_guid": str(result.target_object_guid),
            "resolved_dn_before": result.resolved_dn_before,
            "resolved_dn_after": result.resolved_dn_after,
            "changed_fields": list(result.changed_fields),
            "verification_evidence": evidence,
            "source_dc": result.source_dc,
            "committed_at": result.committed_at.isoformat() if result.committed_at else None,
            "verified_at": result.verified_at.isoformat() if result.verified_at else None,
            "warnings": list(result.warnings),
            "rollback_status": result.rollback_status,
            "entra_evidence_hint": hint,
        }

    # --- operations --------------------------------------------------------

    def _operation_item(self, stored: Any, record: Any) -> dict[str, Any]:  # noqa: ANN401 - store rows duck-typed.
        """Build the redacted operation view shared by get/search."""
        evidence = (
            record.verification_evidence.model_dump(mode="json")
            if record is not None and record.verification_evidence
            else None
        )
        return {
            "operation_id": str(stored.operation_id),
            "state": str(stored.state),
            "capability": str(stored.capability) or None,
            "disposition": None,
            "target_object_guid": str(record.target_guid) if record is not None and record.target_guid else None,
            "verification_evidence": evidence,
            "error_code": record.error_code if record is not None else None,
            "created_at": stored.created_at,
            "updated_at": stored.updated_at,
        }

    async def get_operation(self, operation_id: str, caller: Any) -> dict[str, Any] | None:  # noqa: ANN401
        """Fetch one operation record bound to the caller tenant/connector."""
        stored = await self._repository.store.get(operation_id)
        if stored is None:
            return None
        domain_caller = caller_to_domain(caller, self._settings, now=self._clock.now())
        if str(stored.tenant_id) != domain_caller.tenant_id or str(stored.connector_id) != domain_caller.connector_id:
            return None
        item = self._operation_item(stored, self._repository.cached(operation_id))
        return redact_dict(item)

    async def search_operations(
        self,
        filters: Mapping[str, str],
        page_size: int,
        page_token: Any,  # noqa: ANN401 - decoded cursor dict or None.
        caller: Any,  # noqa: ANN401
    ) -> dict[str, Any]:
        """Search operations by allowlisted filters with offset paging."""
        domain_caller = caller_to_domain(caller, self._settings, now=self._clock.now())
        normalized = {str(key): str(value) for key, value in filters.items()}
        unknown = sorted(set(normalized) - OPERATION_SEARCH_FILTERS)
        if unknown:
            raise RequestInvalidError(f"unsupported operation search filters: {', '.join(unknown)}")
        offset = 0
        if isinstance(page_token, Mapping):
            try:
                offset = max(0, int(page_token.get("offset") or 0))
            except (TypeError, ValueError) as exc:
                raise RequestInvalidError("invalid page cursor") from exc
        limit = max(1, min(int(page_size), 1000))
        rows = await self._repository.store.list(
            tenant_id=domain_caller.tenant_id,
            connector_id=domain_caller.connector_id,
            state=normalized.get("state"),
            limit=limit + 1,
            offset=offset,
        )
        matched = [row for row in rows if self._matches_filters(row, normalized)]
        has_more = len(matched) > limit
        items = [
            redact_dict(self._operation_item(row, self._repository.cached(str(row.operation_id))))
            for row in matched[:limit]
        ]
        return {"items": items, "next_cursor": {"offset": offset + limit} if has_more else None}

    def _matches_filters(self, row: Any, filters: Mapping[str, str]) -> bool:  # noqa: ANN401 - store row duck-typed.
        """Apply the allowlisted filters not expressible in SQL."""
        capability = filters.get("capability")
        if capability and str(row.capability) != capability:
            return False
        record = self._repository.cached(str(row.operation_id))
        ticket = filters.get("ticket_id")
        if ticket and (record is None or (record.ticket_id or "") != ticket):
            return False
        target_guid = filters.get("target_guid")
        if target_guid and (record is None or record.target_guid is None or str(record.target_guid) != target_guid):
            return False
        created = row.created_at if row.created_at.tzinfo is not None else row.created_at.replace(tzinfo=UTC)
        requested_from = filters.get("requested_from")
        if requested_from and created < parse_bound(requested_from, "requested_from"):
            return False
        requested_to = filters.get("requested_to")
        return not (requested_to and created > parse_bound(requested_to, "requested_to"))

    # --- audit -------------------------------------------------------------

    async def get_audit(self, audit_id: str, caller: Any) -> dict[str, Any] | None:  # noqa: ANN401
        """Fetch one redacted audit record bound to the caller boundary."""
        payload = await self._audit_store.get(audit_id)
        if payload is None:
            return None
        domain_caller = caller_to_domain(caller, self._settings, now=self._clock.now())
        tenant = str(payload.get("tenant_id") or "")
        connector = str(payload.get("connector_id") or "")
        if tenant and tenant != domain_caller.tenant_id:
            return None
        if connector and connector != domain_caller.connector_id:
            return None
        entry = {str(key): value for key, value in payload.items() if not str(key).startswith("_")}
        chain = str(payload.get("_entry_hash") or "") or None
        return redact_dict(
            {
                "audit_id": str(payload.get("_entry_key") or audit_id),
                "operation_id": payload.get("operation_id"),
                "entries": [entry],
                "chain_reference": chain,
            }
        )

    async def export_audit(self, params: Mapping[str, Any], caller: Any) -> dict[str, Any]:  # noqa: ANN401
        """Request a bounded audit export receipt (content stays server-side)."""
        domain_caller = caller_to_domain(caller, self._settings, now=self._clock.now())
        await self._audit_store.export(
            tenant_id=domain_caller.tenant_id,
            connector_id=domain_caller.connector_id,
            limit=200,
        )
        export_id = f"exp-{uuid4().hex[:12]}"
        return {"export_id": export_id, "state": "RECEIVED", "status_url": f"/api/v1/operations/{export_id}"}

    # --- health ------------------------------------------------------------

    async def get_health(self) -> dict[str, Any]:
        """Return redacted liveness information."""
        from mwa_ad_connector import __version__  # noqa: PLC0415 - avoids import cycle at module load.

        return {"status": "HEALTHY", "version": __version__, "connector_id": self._settings.connector_id}

    async def get_readiness(self) -> dict[str, Any]:
        """Return readiness checks with redacted details (fail-closed)."""
        timeout = min(self._settings.ldap_connect_timeout_seconds, _READINESS_TIMEOUT_SECONDS)
        checks = await collect_readiness(
            settings=self._settings,
            gateway=self._gateway,
            operation_store=self._repository.store,
            audit_store=self._audit_store,
            timeout=timeout,
        )
        return {"ready": all(bool(check["healthy"]) for check in checks), "checks": checks}
