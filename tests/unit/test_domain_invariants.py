"""Unit tests for domain invariants (Steps 1-2 smoke coverage)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from mwa_ad_connector.domain.capabilities import is_mutation_capability
from mwa_ad_connector.domain.enums import IdentifierType, ObjectType, OperationState
from mwa_ad_connector.domain.errors import ErrorCode, http_status_for, is_retryable
from mwa_ad_connector.domain.identifiers import ObjectReference
from mwa_ad_connector.domain.operations import (
    CapabilityRequest,
    OperationRecord,
    StateTransition,
    is_legal_transition,
    is_terminal,
)


def _timestamps() -> tuple[datetime, datetime]:
    """Return a valid (requested_at, expires_at) pair."""
    now = datetime.now(timezone.utc)
    return now, now


def _request_kwargs() -> dict[str, object]:
    """Build base CapabilityRequest kwargs for a read capability."""
    requested, expires = _timestamps()
    guid = uuid4()
    return {
        "capability": "user.get",
        "customer_id": "customer-lab",
        "tenant_id": "tenant-lab",
        "connector_id": "connector-lab-01",
        "forest_id": "forest-lab",
        "domain_id": "domain-lab",
        "target": ObjectReference(object_type=ObjectType.USER, object_guid=guid, domain_id="d", forest_id="f"),
        "correlation_id": "corr-1",
        "requested_at": requested,
        "expires_at": expires,
        "nonce": "nonce-12345678",
        "requested_by": "tester",
    }


def test_object_reference_requires_guid_or_pair() -> None:
    """GUID-less references without identifier pairs are rejected."""
    with pytest.raises(ValidationError):
        ObjectReference(object_type=ObjectType.USER, domain_id="d", forest_id="f")


def test_object_reference_dn_never_primary() -> None:
    """A lone expected_dn does not satisfy identity invariants."""
    with pytest.raises(ValidationError):
        ObjectReference(object_type=ObjectType.USER, domain_id="d", forest_id="f", expected_dn="CN=x,DC=lab,DC=local")


def test_object_reference_identifier_pair_ok() -> None:
    """Identifier pair references validate and require resolution."""
    ref = ObjectReference(
        object_type=ObjectType.USER,
        identifier_type=IdentifierType.UPN,
        identifier_value="jdoe@lab.local",
        domain_id="domain-lab",
        forest_id="forest-lab",
    )
    assert ref.requires_resolution
    assert not ref.has_stable_identity


def test_capability_request_unknown_capability_rejected() -> None:
    """Unknown capabilities fail envelope validation."""
    kwargs: dict[str, object] = dict(_request_kwargs())
    kwargs["capability"] = "ldap.raw.query"
    with pytest.raises(ValidationError):
        CapabilityRequest(**kwargs)


def test_capability_request_mutation_requires_bindings() -> None:
    """Mutations require idempotency key, ticket and target GUID."""
    requested, expires = _timestamps()
    guid = uuid4()
    with pytest.raises(ValidationError):
        CapabilityRequest(
            capability="group.member.add",
            customer_id="c",
            tenant_id="t",
            connector_id="conn",
            forest_id="f",
            domain_id="d",
            target=ObjectReference(object_type=ObjectType.GROUP, object_guid=guid, domain_id="d", forest_id="f"),
            correlation_id="corr",
            requested_at=requested,
            expires_at=expires,
            nonce="nonce-12345678",
            requested_by="tester",
        )


def test_operation_record_rejects_illegal_transition() -> None:
    """Discontinuous history chains are rejected."""
    now = datetime.now(timezone.utc)
    guid = uuid4()
    with pytest.raises(ValidationError):
        OperationRecord(
            operation_id="op-1",
            customer_id="c",
            tenant_id="t",
            connector_id="conn",
            forest_id="f",
            domain_id="d",
            capability="group.member.add",
            risk="HIGH",
            request_hash="hash",
            idempotency_key=str(guid),
            correlation_id="corr",
            caller_subject="tester",
            state="AD_VERIFIED",
            history=[StateTransition(from_state=None, to_state=OperationState.RECEIVED, at=now)],
            created_at=now,
            updated_at=now,
            deadline=now,
        )


def test_error_taxonomy_mapping() -> None:
    """Spot-check HTTP/retry mapping from Section 8.7."""
    assert http_status_for(ErrorCode.TARGET_NOT_FOUND) == 404
    assert http_status_for(ErrorCode.LDAP_UNAVAILABLE) == 503
    assert is_retryable(ErrorCode.LDAP_UNAVAILABLE)
    assert not is_retryable(ErrorCode.REQUEST_INVALID)
    assert not is_mutation_capability("user.get")
    assert is_mutation_capability("group.member.add")
    assert is_terminal(OperationState.FAILED)
    assert is_legal_transition(OperationState.RECEIVED, OperationState.AUTHORIZED)
