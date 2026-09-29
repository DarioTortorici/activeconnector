"""Dispatch validated envelopes to the operation orchestrator."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from mwa_ad_connector.application.commands.envelope import CommandEnvelope
from mwa_ad_connector.application.services.operation_service import MutateFn, OperationService, VerifyFn
from mwa_ad_connector.domain.capabilities import is_known_capability
from mwa_ad_connector.domain.errors import DomainError, ErrorCode, RequestInvalidError
from mwa_ad_connector.domain.operations import CallerContext, CapabilityRequest, MutationResult

ExecutorFn = Callable[[CapabilityRequest, CallerContext], Awaitable[tuple[MutateFn, VerifyFn | None]]]


class BindingMismatchError(DomainError):
    """Envelope scope does not match the authenticated caller binding."""

    code = ErrorCode.TENANT_BINDING_MISMATCH


class CommandDispatcher:
    """Route envelopes to capability executors via OperationService.

    Executors build ``(mutate, verify)`` callbacks without executing; the
    orchestrator runs them inside the state machine so each mutation is
    committed exactly once per idempotency key.

    Args:
        operation_service: Canonical orchestrator.
        executors: Mapping capability -> executor callback factory.
    """

    def __init__(self, operation_service: OperationService, executors: dict[str, ExecutorFn] | None = None) -> None:
        self._operations = operation_service
        self._executors: dict[str, ExecutorFn] = dict(executors or {})

    def register(self, capability: str, executor: ExecutorFn) -> None:
        """Register an executor for a capability.

        Args:
            capability: Allowlisted capability name.
            executor: Factory ``(request, caller) -> (mutate, verify)``.

        Raises:
            RequestInvalidError: If the capability is not allowlisted.
        """
        if not is_known_capability(capability):
            raise RequestInvalidError(f"capability not allowlisted: {capability}")
        self._executors[capability] = executor

    async def dispatch(self, envelope: CommandEnvelope, caller: CallerContext) -> MutationResult:
        """Dispatch an envelope with authenticated caller context.

        Args:
            envelope: Validated command envelope.
            caller: Authenticated caller (tenant/connector binding verified).

        Returns:
            Domain ``MutationResult`` from the operation service.

        Raises:
            BindingMismatchError: On tenant/connector binding mismatch.
            RequestInvalidError: When no executor is wired for the capability.
        """
        self._check_binding(envelope, caller)
        executor = self._executors.get(envelope.capability)
        if executor is None:
            raise RequestInvalidError(f"no executor wired for capability: {envelope.capability}")
        request = envelope.to_capability_request()
        mutate, verify = await executor(request, caller)
        return await self._operations.execute(request, caller, mutate, verify)

    @staticmethod
    def _check_binding(envelope: CommandEnvelope, caller: CallerContext) -> None:
        if envelope.tenant_id != caller.tenant_id:
            raise BindingMismatchError("envelope tenant does not match caller binding")
        if envelope.connector_id != caller.connector_id:
            raise BindingMismatchError("envelope connector does not match caller binding")
