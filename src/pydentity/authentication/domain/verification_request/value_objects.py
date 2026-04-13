from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from uuid import UUID

from pydentity.shared_kernel.building_blocks import ValueObject
from pydentity.shared_kernel.guards import (
    guard_not_blank,
    guard_not_none,
    guard_positive,
)


class VerificationRequestStatus(StrEnum):
    PENDING = auto()
    VERIFIED = auto()
    INVALIDATED = auto()
    EXPIRED = auto()


class VerificationRequestType(StrEnum):
    EMAIL_VERIFICATION = auto()
    PASSWORD_RESET = auto()


class VerificationFailureReason(StrEnum):
    INVALID_TOKEN = auto()
    EXPIRED = auto()
    ALREADY_VERIFIED = auto()


@dataclass(frozen=True, slots=True)
class VerificationRequestId(ValueObject):
    value: UUID

    def __post_init__(self) -> None:
        guard_not_none(self.value)


@dataclass(frozen=True, slots=True)
class RawVerificationRequestToken(ValueObject):
    value: str

    def __post_init__(self) -> None:
        guard_not_blank(self.value)


@dataclass(frozen=True, slots=True)
class HashedVerificationRequestToken(ValueObject):
    value: str

    def __post_init__(self) -> None:
        guard_not_blank(self.value)


@dataclass(frozen=True, slots=True)
class VerificationPolicy(ValueObject):
    email_verification_ttl_seconds: int
    password_reset_ttl_seconds: int

    def __post_init__(self) -> None:
        guard_positive(self.email_verification_ttl_seconds)
        guard_positive(self.password_reset_ttl_seconds)


@dataclass(frozen=True, slots=True)
class VerificationRequestExpiry(ValueObject):
    value: datetime
