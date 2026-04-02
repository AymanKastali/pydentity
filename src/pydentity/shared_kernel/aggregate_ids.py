from dataclasses import dataclass
from uuid import UUID

from pydentity.shared_kernel.building_blocks import ValueObject


@dataclass(frozen=True, slots=True)
class IdentityId(ValueObject):
    value: UUID


@dataclass(frozen=True, slots=True)
class AccountId(ValueObject):
    value: UUID
