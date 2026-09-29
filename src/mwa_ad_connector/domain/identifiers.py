"""Object identity contracts.

objectGUID is the stable primary identity. A caller-supplied DN is
accepted only as an ``expected_dn`` safeguard and must never bypass
the resolver.
"""

from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mwa_ad_connector.domain.enums import IdentifierType, ObjectType


class ObjectReference(BaseModel):
    """Reference to a directory object without trusting caller DNs.

    Attributes:
        object_type: Category of the referenced object.
        object_guid: Stable AD identity; preferred for mutations.
        identifier_type: Allowlisted lookup kind when GUID is absent.
        identifier_value: Normalized lookup value for the identifier kind.
        domain_id: Owning domain boundary.
        forest_id: Owning forest boundary.
        expected_dn: Optional safeguard; never used as primary identity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    object_type: ObjectType
    object_guid: UUID | None = None
    identifier_type: IdentifierType | None = None
    identifier_value: str | None = Field(default=None, min_length=1, max_length=256)
    domain_id: str = Field(min_length=1, max_length=128)
    forest_id: str = Field(min_length=1, max_length=128)
    expected_dn: str | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def _check_identity_invariants(self) -> Self:
        """Enforce GUID-or-identifier-pair and DN safeguard invariants.

        Returns:
            The validated model instance.

        Raises:
            ValueError: When neither GUID nor identifier pair is present,
                or when only half of the identifier pair is supplied.
        """
        has_guid = self.object_guid is not None
        has_kind = self.identifier_type is not None
        raw = self.identifier_value
        has_value = raw is not None and raw.strip() != ""
        if not has_guid and not (has_kind and has_value):
            raise ValueError("Either object_guid or identifier_type+identifier_value is required")
        if has_kind != has_value:
            raise ValueError("identifier_type and identifier_value must be provided together")
        return self

    @property
    def has_stable_identity(self) -> bool:
        """Whether the reference carries the stable objectGUID."""
        return self.object_guid is not None

    @property
    def requires_resolution(self) -> bool:
        """Whether the resolver must translate an identifier to a GUID."""
        return self.object_guid is None
