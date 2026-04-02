from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from typing import ClassVar

from pydentity.authentication.domain.authentication_attempt.errors import (
    AttemptNotInProgressError,
    FactorAlreadyVerifiedError,
    FactorNotRequiredError,
)
from pydentity.shared_kernel import (
    ValueObject,
    guard_no_duplicates,
    guard_not_empty,
    guard_not_empty_collection,
    guard_within_max_length,
    guard_within_max_size,
)


class AttemptStatus(StrEnum):
    IN_PROGRESS = auto()
    SUCCEEDED = auto()
    FAILED = auto()
    EXPIRED = auto()

    def guard_is_in_progress(self) -> None:
        if not self.is_in_progress:
            raise AttemptNotInProgressError()

    @property
    def is_in_progress(self) -> bool:
        return self is AttemptStatus.IN_PROGRESS

    @property
    def is_succeeded(self) -> bool:
        return self is AttemptStatus.SUCCEEDED

    @property
    def is_failed(self) -> bool:
        return self is AttemptStatus.FAILED

    @property
    def is_expired(self) -> bool:
        return self is AttemptStatus.EXPIRED


class AuthenticationFactor(StrEnum):
    KNOWLEDGE = auto()  # Password, PIN, security question
    POSSESSION = auto()  # TOTP app, SMS code, email code, hardware key
    INHERENCE = auto()  # Fingerprint, face scan, voice recognition


@dataclass(frozen=True, slots=True)
class RequiredFactors(ValueObject):
    _MAX_SIZE: ClassVar[int] = 3

    factors: tuple[AuthenticationFactor, ...]

    def __post_init__(self) -> None:
        guard_not_empty_collection(self.factors)
        guard_no_duplicates(self.factors)
        guard_within_max_size(self.factors, self._MAX_SIZE)

    def contains(self, factor: AuthenticationFactor) -> bool:
        return factor in self.factors

    def is_satisfied_by(self, verified: VerifiedFactors) -> bool:
        return set(self.factors) == set(verified.factors)

    def guard_contains(self, factor: AuthenticationFactor) -> None:
        if not self.contains(factor):
            raise FactorNotRequiredError()


@dataclass(frozen=True, slots=True)
class VerifiedFactors(ValueObject):
    _MAX_SIZE: ClassVar[int] = 3

    factors: tuple[AuthenticationFactor, ...]

    def __post_init__(self) -> None:
        guard_no_duplicates(self.factors)
        guard_within_max_size(self.factors, self._MAX_SIZE)

    @classmethod
    def initialize(cls) -> VerifiedFactors:
        return cls(factors=())

    def has_factor(self, factor: AuthenticationFactor) -> bool:
        return factor in self.factors

    def with_factor(self, factor: AuthenticationFactor) -> VerifiedFactors:
        return VerifiedFactors(factors=(*self.factors, factor))

    def guard_factor_not_verified(self, factor: AuthenticationFactor) -> None:
        if self.has_factor(factor):
            raise FactorAlreadyVerifiedError()


@dataclass(frozen=True, slots=True)
class HashedVerificationCode(ValueObject):
    _MAX_LENGTH: ClassVar[int] = 256

    value: str

    def __post_init__(self) -> None:
        guard_not_empty(self.value)
        guard_within_max_length(self.value, self._MAX_LENGTH)


@dataclass(frozen=True, slots=True)
class VerificationCode(ValueObject):
    hashed_value: HashedVerificationCode
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def is_active(self, now: datetime) -> bool:
        return not self.is_expired(now)
