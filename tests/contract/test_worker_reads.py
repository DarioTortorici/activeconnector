"""Contract: the worker dispatcher accepts read results that carry no operation_id."""

from __future__ import annotations

from typing import Any

import pytest

from mwa_ad_connector.infrastructure.transport.worker import OperationServiceDispatcher

pytestmark = pytest.mark.contract

READ_GUID = "91faf0e8-cfb6-49ea-80a7-e621986443f8"


class _ReadService:
    """Fake operation service returning a read dict (no operation_id/state)."""

    async def execute_capability(self, **kwargs: Any) -> dict[str, Any]:
        """Return a read-shaped result regardless of the request."""
        _ = kwargs
        return {"object_type": "USER", "object_guid": READ_GUID}


class _MutationStateWithoutId:
    """Fake service claiming a mutation state without an operation id."""

    async def execute_capability(self, **kwargs: Any) -> dict[str, Any]:
        """Return a malformed mutation-shaped result."""
        _ = kwargs
        return {"state": "AD_VERIFIED"}


async def test_dispatcher_returns_read_result_without_operation_id() -> None:
    """A read result is passed through untouched instead of being rejected."""
    result = await OperationServiceDispatcher(_ReadService()).dispatch({"capability": "user.resolve"})
    assert result == {"object_type": "USER", "object_guid": READ_GUID}


async def test_dispatcher_rejects_mutation_state_without_operation_id() -> None:
    """A result claiming a mutation state but lacking an operation_id is rejected."""
    with pytest.raises(ValueError, match="malformed"):
        await OperationServiceDispatcher(_MutationStateWithoutId()).dispatch({"capability": "account.unlock"})


async def test_dispatcher_rejects_non_mapping_result() -> None:
    """A result that is not a mapping is rejected outright."""

    class _NotAMapping:
        async def execute_capability(self, **kwargs: Any) -> Any:
            _ = kwargs
            return ["not", "a", "dict"]

    with pytest.raises(ValueError, match="malformed"):
        await OperationServiceDispatcher(_NotAMapping()).dispatch({"capability": "user.resolve"})
