from dataclasses import dataclass
from enum import StrEnum, auto

from pydentity.shared_kernel.building_blocks import ValueObject
from pydentity.shared_kernel.guards import guard_not_blank, guard_positive


class DeviceStatus(StrEnum):
    ACTIVE = auto()
    REVOKED = auto()


class DeviceRevocationReason(StrEnum):
    MANUAL = auto()
    ADMIN = auto()
    LOCKOUT = auto()
    CLOSURE = auto()


@dataclass(frozen=True, slots=True)
class RawDeviceFingerprint(ValueObject):
    value: str

    def __post_init__(self) -> None:
        guard_not_blank(self.value)


@dataclass(frozen=True, slots=True)
class HashedDeviceFingerprint(ValueObject):
    value: str

    def __post_init__(self) -> None:
        guard_not_blank(self.value)


@dataclass(frozen=True, slots=True)
class DevicePolicy(ValueObject):
    max_devices_per_account: int

    def __post_init__(self) -> None:
        guard_positive(self.max_devices_per_account)
