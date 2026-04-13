from dataclasses import dataclass
from enum import StrEnum, auto
from typing import ClassVar, Final
from uuid import UUID

from pydentity.shared_kernel.building_blocks import ValueObject
from pydentity.shared_kernel.guards import (
    guard_min_not_greater_than_max,
    guard_not_blank,
    guard_not_negative,
    guard_not_none,
    guard_positive,
    guard_within_max_length,
)


class AccountStatus(StrEnum):
    PENDING_VERIFICATION = auto()
    ACTIVE = auto()
    LOCKED = auto()
    SUSPENDED = auto()
    CLOSED = auto()


class LockReason(StrEnum):
    THRESHOLD = auto()
    ADMIN = auto()


class UnlockReason(StrEnum):
    EXPIRY = auto()
    ADMIN = auto()


@dataclass(frozen=True, slots=True)
class CredentialId(ValueObject):
    value: UUID

    def __post_init__(self) -> None:
        guard_not_none(self.value)


@dataclass(frozen=True, slots=True)
class Email(ValueObject):
    _MAX_LENGTH: ClassVar[Final[int]] = 254

    value: str

    def __post_init__(self) -> None:
        guard_not_blank(self.value)
        guard_within_max_length(self.value, self._MAX_LENGTH)
        self._guard_email_format()

    def _guard_email_format(self) -> None:
        parts = self.value.split("@")
        if len(parts) != 2 or not parts[0] or "." not in parts[1]:
            raise ValueError(f"'{self.value}' is not a valid email format.")


@dataclass(frozen=True, slots=True)
class RawPassword(ValueObject):
    value: str

    def __post_init__(self) -> None:
        guard_not_blank(self.value)


@dataclass(frozen=True, slots=True)
class HashedPassword(ValueObject):
    value: str

    def __post_init__(self) -> None:
        guard_not_blank(self.value)


@dataclass(frozen=True, slots=True)
class FailedAttemptCount(ValueObject):
    value: int

    def __post_init__(self) -> None:
        guard_not_negative(self.value)


@dataclass(frozen=True, slots=True)
class PasswordPolicy(ValueObject):
    min_length: int
    max_length: int
    max_history: int

    def __post_init__(self) -> None:
        guard_positive(self.min_length)
        guard_positive(self.max_length)
        guard_positive(self.max_history)
        guard_min_not_greater_than_max(self.min_length, self.max_length)


@dataclass(frozen=True, slots=True)
class LockoutPolicy(ValueObject):
    max_failed_attempts: int
    lockout_duration_seconds: int

    def __post_init__(self) -> None:
        guard_positive(self.max_failed_attempts)
        guard_positive(self.lockout_duration_seconds)
