"""Idempotency: canonical request hashing plus reserve/check (Step 9).

Uniqueness scope is ``(tenant_id, connector_id, idempotency_key)``. The
same key with the same canonical payload hash replays the original
operation; the same key with a different hash raises
:class:`IdempotencyCollision`. Atomicity lives in the repository
implementation (unique constraint + single statement/transaction).

The :class:`OperationRepository` protocol mirrors
``application.ports.operation_repository`` (owned by another agent);
unify on it when available.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Mapping
from datetime import date, datetime
from enum import Enum
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class IdempotencyCollision(Exception):
    """Raised when an idempotency key is reused with a different payload."""

    def __init__(self, operation_id: str | None, *, reason: str = "idempotency key reused") -> None:
        super().__init__(f"{reason} for operation {operation_id!r}")
        self.code = "IDEMPOTENCY_COLLISION"
        self.operation_id = operation_id


class IdempotencyClaim(BaseModel):
    """Outcome of claiming an idempotency key."""

    model_config = ConfigDict(extra="forbid")

    created: bool
    operation_id: str = Field(min_length=1)
    stored_hash: str = Field(min_length=1)


class OperationRepository(Protocol):
    """Persistence port needed for idempotent reservation."""

    async def claim_idempotency(
        self,
        *,
        tenant_id: str,
        connector_id: str,
        idempotency_key: str,
        request_hash: str,
        operation_id: str,
    ) -> IdempotencyClaim:
        """Atomically insert or fetch the reservation for the key."""
        ...  # pragma: no cover

    async def find_idempotency(
        self,
        *,
        tenant_id: str,
        connector_id: str,
        idempotency_key: str,
    ) -> IdempotencyClaim | None:
        """Return the existing claim for the key, if any."""
        ...  # pragma: no cover


_MAX_IDEMPOTENCY_KEY_LENGTH = 128


def _json_default(value: Any) -> Any:
    result: Any = None
    if isinstance(value, (datetime, date)):
        result = value.isoformat()
    elif isinstance(value, UUID):
        result = str(value)
    elif isinstance(value, Enum):
        result = value.value
    elif isinstance(value, (bytes, bytearray)):
        result = {"__bytes_sha256__": hashlib.sha256(bytes(value)).hexdigest()}
    elif isinstance(value, Mapping):
        result = dict(value)
    elif isinstance(value, (set, frozenset)):
        result = sorted(value, key=repr)
    else:
        result = str(value)
    return result


def canonical_request_hash(
    payload: Mapping[str, Any],
    *,
    exclude: Collection[str] = (),
) -> str:
    """Return the SHA-256 hex digest of the canonical JSON of ``payload``.

    Canonical form: keys sorted, compact separators, UTF-8. Volatile
    envelope fields (nonce, timestamps) must be listed in ``exclude`` by
    the caller so retries hash identically. Secret-bearing values are
    hashed by digest (bytes) or not at all: never pass raw passwords here;
    pass only operation metadata and non-secret parameters.
    """
    excluded = set(exclude)
    sanitized = {key: value for key, value in payload.items() if key not in excluded}
    canonical = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=_json_default)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_key(tenant_id: str, connector_id: str, idempotency_key: str) -> None:
    if not tenant_id.strip() or not connector_id.strip():
        raise ValueError("tenant_id and connector_id must be non-empty")
    if not idempotency_key.strip() or len(idempotency_key) > _MAX_IDEMPOTENCY_KEY_LENGTH:
        raise ValueError(f"idempotency_key must be 1..{_MAX_IDEMPOTENCY_KEY_LENGTH} characters")


async def reserve(  # noqa: PLR0913 - explicit idempotency dimensions
    repository: OperationRepository,
    *,
    tenant_id: str,
    connector_id: str,
    idempotency_key: str,
    request_hash: str,
    operation_id: str,
) -> IdempotencyClaim:
    """Claim the idempotency key or return the existing reservation.

    Raises:
        IdempotencyCollision: When the key exists with a different hash.
    """
    _validate_key(tenant_id, connector_id, idempotency_key)
    claim = await repository.claim_idempotency(
        tenant_id=tenant_id,
        connector_id=connector_id,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        operation_id=operation_id,
    )
    if not claim.created and claim.stored_hash != request_hash:
        raise IdempotencyCollision(claim.operation_id, reason="idempotency key reused with different payload")
    return claim


async def check(
    repository: OperationRepository,
    *,
    tenant_id: str,
    connector_id: str,
    idempotency_key: str,
    request_hash: str,
) -> IdempotencyClaim | None:
    """Look up an existing claim without creating one (read-only probe).

    Raises:
        IdempotencyCollision: When the key exists with a different hash.
    """
    _validate_key(tenant_id, connector_id, idempotency_key)
    claim = await repository.find_idempotency(
        tenant_id=tenant_id, connector_id=connector_id, idempotency_key=idempotency_key
    )
    if claim is not None and claim.stored_hash != request_hash:
        raise IdempotencyCollision(claim.operation_id, reason="idempotency key reused with different payload")
    return claim
