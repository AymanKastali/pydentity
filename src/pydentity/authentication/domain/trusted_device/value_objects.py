from dataclasses import dataclass
from enum import StrEnum, auto
from typing import ClassVar

from pydentity.authentication.domain.trusted_device.errors import (
    DeviceAlreadyExpiredError,
    DeviceAlreadyRevokedError,
    DeviceLimitExceededError,
)
from pydentity.shared_kernel import (
    ValueObject,
    guard_not_blank,
    guard_positive,
    guard_within_max_length,
)


@dataclass(frozen=True, slots=True)
class DeviceFingerprint(ValueObject):
    _MAX_LENGTH: ClassVar[int] = 256

    value: str

    def __post_init__(self) -> None:
        guard_not_blank(self.value)
        guard_within_max_length(self.value, self._MAX_LENGTH)


class TrustedDeviceStatus(StrEnum):
    REGISTERED = auto()
    REVOKED = auto()
    EXPIRED = auto()

    def guard_not_revoked(self) -> None:
        if self.is_revoked:
            raise DeviceAlreadyRevokedError()

    def guard_not_expired(self) -> None:
        if self.is_expired:
            raise DeviceAlreadyExpiredError()

    @property
    def is_registered(self) -> bool:
        return self is TrustedDeviceStatus.REGISTERED

    @property
    def is_revoked(self) -> bool:
        return self is TrustedDeviceStatus.REVOKED

    @property
    def is_expired(self) -> bool:
        return self is TrustedDeviceStatus.EXPIRED


@dataclass(frozen=True, slots=True)
class DevicePolicy(ValueObject):
    max_devices: int

    def __post_init__(self) -> None:
        guard_positive(self.max_devices)

    def is_limit_exceeded(self, active_count: int) -> bool:
        return active_count >= self.max_devices

    def guard_limit_not_exceeded(self, active_count: int) -> None:
        if self.is_limit_exceeded(active_count):
            raise DeviceLimitExceededError()


class DeviceRevocationReason(StrEnum):
    MANUAL = auto()
    ADMIN = auto()
    LOCKOUT = auto()
    CLOSURE = auto()
    PASSWORD_CHANGED = auto()
    MFA_RECONFIGURED = auto()
    LIMIT_EXCEEDED = auto()
