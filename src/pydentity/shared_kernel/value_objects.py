from dataclasses import dataclass
from uuid import UUID

from pydentity.shared_kernel.building_blocks import ValueObject
from pydentity.shared_kernel.guards import guard_not_none


@dataclass(frozen=True, slots=True)
class AccountId(ValueObject):
    value: UUID

    def __post_init__(self) -> None:
        guard_not_none(self.value)


@dataclass(frozen=True, slots=True)
class DeviceId(ValueObject):
    value: UUID

    def __post_init__(self) -> None:
        guard_not_none(self.value)
