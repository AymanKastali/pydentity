from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum, auto
from typing import ClassVar

from pydentity.authentication.domain.account.errors import (
    AccountAlreadyClosedError,
    AccountAlreadySuspendedError,
    AccountNotActiveError,
    AccountNotLockedError,
    AccountNotUnverifiedError,
    AccountUnverifiedError,
    PasswordPolicyViolationError,
)
from pydentity.shared_kernel import (
    ValueObject,
    guard_all_positive,
    guard_all_within_max,
    guard_min_not_greater_than_max,
    guard_not_empty,
    guard_not_empty_collection,
    guard_not_negative,
    guard_positive,
    guard_within_max,
    guard_within_max_length,
    guard_within_max_size,
    guard_within_min,
)


class AccountStatus(StrEnum):
    UNVERIFIED = auto()
    ACTIVE = auto()
    LOCKED = auto()
    SUSPENDED = auto()
    CLOSED = auto()

    # --- Queries ---

    @property
    def is_unverified(self) -> bool:
        return self is AccountStatus.UNVERIFIED

    @property
    def is_active(self) -> bool:
        return self is AccountStatus.ACTIVE

    @property
    def is_locked(self) -> bool:
        return self is AccountStatus.LOCKED

    @property
    def is_suspended(self) -> bool:
        return self is AccountStatus.SUSPENDED

    @property
    def is_closed(self) -> bool:
        return self is AccountStatus.CLOSED

    # --- Guards ---

    def guard_is_unverified(self) -> None:
        if not self.is_unverified:
            raise AccountNotUnverifiedError()

    def guard_is_active(self) -> None:
        if not self.is_active:
            raise AccountNotActiveError()

    def guard_is_locked(self) -> None:
        if not self.is_locked:
            raise AccountNotLockedError()

    def guard_not_unverified(self) -> None:
        if self.is_unverified:
            raise AccountUnverifiedError()

    def guard_not_suspended(self) -> None:
        if self.is_suspended:
            raise AccountAlreadySuspendedError()

    def guard_not_closed(self) -> None:
        if self.is_closed:
            raise AccountAlreadyClosedError()


class LockReason(StrEnum):
    ADMIN = auto()
    THRESHOLD = auto()


class UnlockReason(StrEnum):
    ADMIN = auto()
    EXPIRY = auto()


@dataclass(frozen=True, slots=True)
class EmailAddress(ValueObject):
    _MAX_LENGTH: ClassVar[int] = 254
    _MAX_LOCAL_PART_LENGTH: ClassVar[int] = 64
    _MAX_DOMAIN_LENGTH: ClassVar[int] = 253
    _MAX_DOMAIN_LABEL_LENGTH: ClassVar[int] = 63

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", self.value.strip().lower())
        guard_not_empty(self.value)
        guard_within_max_length(self.value, self._MAX_LENGTH)
        self._guard_has_valid_structure()

    def _guard_has_valid_structure(self) -> None:
        parts: list[str] = self.value.split("@")
        self._guard_has_exactly_one_at_sign(parts)
        self._guard_local_part_valid(parts[0])
        self._guard_domain_valid(parts[1])

    # --- At sign ---

    def _guard_has_exactly_one_at_sign(self, parts: list[str]) -> None:
        if len(parts) != 2:
            raise ValueError("Email address must contain exactly one '@'.")

    # --- Local part ---

    def _guard_local_part_valid(self, local: str) -> None:
        self._guard_local_part_not_empty(local)
        self._guard_local_part_within_max_length(local)
        self._guard_local_part_has_no_leading_dot(local)
        self._guard_local_part_has_no_trailing_dot(local)
        self._guard_local_part_has_no_consecutive_dots(local)

    def _guard_local_part_not_empty(self, local: str) -> None:
        guard_not_empty(local)

    def _guard_local_part_within_max_length(self, local: str) -> None:
        guard_within_max_length(local, self._MAX_LOCAL_PART_LENGTH)

    def _guard_local_part_has_no_leading_dot(self, local: str) -> None:
        if local.startswith("."):
            raise ValueError("Email local part must not start with a dot.")

    def _guard_local_part_has_no_trailing_dot(self, local: str) -> None:
        if local.endswith("."):
            raise ValueError("Email local part must not end with a dot.")

    def _guard_local_part_has_no_consecutive_dots(self, local: str) -> None:
        if ".." in local:
            raise ValueError("Email local part must not contain consecutive dots.")

    # --- Domain ---

    def _guard_domain_valid(self, domain: str) -> None:
        self._guard_domain_not_empty(domain)
        self._guard_domain_within_max_length(domain)
        self._guard_domain_has_at_least_two_labels(domain)
        self._guard_domain_labels_valid(domain)

    def _guard_domain_not_empty(self, domain: str) -> None:
        guard_not_empty(domain)

    def _guard_domain_within_max_length(self, domain: str) -> None:
        guard_within_max_length(domain, self._MAX_DOMAIN_LENGTH)

    def _guard_domain_has_at_least_two_labels(self, domain: str) -> None:
        if "." not in domain:
            raise ValueError("Email domain must contain at least two labels.")

    def _guard_domain_labels_valid(self, domain: str) -> None:
        labels: list[str] = domain.split(".")
        for label in labels:
            self._guard_domain_label_valid(label)

    # --- Domain label ---

    def _guard_domain_label_valid(self, label: str) -> None:
        self._guard_domain_label_not_empty(label)
        self._guard_domain_label_within_max_length(label)
        self._guard_domain_label_no_leading_hyphen(label)
        self._guard_domain_label_no_trailing_hyphen(label)
        self._guard_domain_label_is_alphanumeric_or_hyphen(label)

    def _guard_domain_label_not_empty(self, label: str) -> None:
        guard_not_empty(label)

    def _guard_domain_label_within_max_length(self, label: str) -> None:
        guard_within_max_length(label, self._MAX_DOMAIN_LABEL_LENGTH)

    def _guard_domain_label_no_leading_hyphen(self, label: str) -> None:
        if label.startswith("-"):
            raise ValueError("Email domain label must not start with a hyphen.")

    def _guard_domain_label_no_trailing_hyphen(self, label: str) -> None:
        if label.endswith("-"):
            raise ValueError("Email domain label must not end with a hyphen.")

    def _guard_domain_label_is_alphanumeric_or_hyphen(self, label: str) -> None:
        if not all(character.isalnum() or character == "-" for character in label):
            raise ValueError(
                "Email domain label must only contain"
                " alphanumeric characters or hyphens."
            )


@dataclass(frozen=True, slots=True)
class HashedPassword(ValueObject):
    _MAX_LENGTH: ClassVar[int] = 256

    value: str

    def __post_init__(self) -> None:
        guard_not_empty(self.value)
        guard_within_max_length(self.value, self._MAX_LENGTH)


@dataclass(frozen=True, slots=True)
class HashedPasswordHistory(ValueObject):
    _MAX_SIZE: ClassVar[int] = 24

    hashes: tuple[HashedPassword, ...]

    def __post_init__(self) -> None:
        guard_within_max_size(self.hashes, self._MAX_SIZE)

    @classmethod
    def initialize(cls) -> HashedPasswordHistory:
        return cls(hashes=())

    def rotate(
        self, current_password: HashedPassword, depth: int
    ) -> HashedPasswordHistory:
        return self.prepend(current_password).truncate(depth)

    def prepend(self, password: HashedPassword) -> HashedPasswordHistory:
        return HashedPasswordHistory(hashes=(password,) + self.hashes)

    def truncate(self, depth: int) -> HashedPasswordHistory:
        return HashedPasswordHistory(hashes=self.hashes[:depth])


@dataclass(frozen=True, slots=True)
class EncryptedTOTPSecret(ValueObject):
    _MAX_LENGTH: ClassVar[int] = 512

    value: bytes

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("Encrypted TOTP secret must not be empty.")
        if len(self.value) > self._MAX_LENGTH:
            raise ValueError(
                f"Encrypted TOTP secret must not exceed {self._MAX_LENGTH} bytes."
            )


@dataclass(frozen=True, slots=True)
class HashedRecoveryCode(ValueObject):
    _MAX_LENGTH: ClassVar[int] = 256

    value: str
    used_at: datetime | None

    def __post_init__(self) -> None:
        guard_not_empty(self.value)
        guard_within_max_length(self.value, self._MAX_LENGTH)

    @property
    def is_unused(self) -> bool:
        return self.used_at is None

    def mark_used(self, now: datetime) -> HashedRecoveryCode:
        return HashedRecoveryCode(value=self.value, used_at=now)


@dataclass(frozen=True, slots=True)
class HashedRecoveryCodeSet(ValueObject):
    _MAX_SIZE: ClassVar[int] = 20

    codes: tuple[HashedRecoveryCode, ...]

    def __post_init__(self) -> None:
        guard_within_max_size(self.codes, self._MAX_SIZE)

    @classmethod
    def initialize(cls) -> HashedRecoveryCodeSet:
        return cls(codes=())

    @property
    def is_empty(self) -> bool:
        return len(self.codes) == 0

    def has_unused(self) -> bool:
        return any(code.is_unused for code in self.codes)

    def with_code_consumed(
        self, consumed_code: HashedRecoveryCode, now: datetime
    ) -> HashedRecoveryCodeSet:
        codes: list[HashedRecoveryCode] = []
        for code in self.codes:
            if code == consumed_code:
                codes.append(code.mark_used(now))
            else:
                codes.append(code)
        return HashedRecoveryCodeSet(codes=tuple(codes))


@dataclass(frozen=True, slots=True)
class LockoutState(ValueObject):
    _MAX_FAILED_ATTEMPTS: ClassVar[int] = 100
    _MAX_LOCKOUT_CYCLES: ClassVar[int] = 50

    count: int
    lockout_count: int
    last_failed_at: datetime | None
    lockout_until: datetime | None

    def __post_init__(self) -> None:
        guard_not_negative(self.count)
        guard_within_max(self.count, self._MAX_FAILED_ATTEMPTS)
        guard_not_negative(self.lockout_count)
        guard_within_max(self.lockout_count, self._MAX_LOCKOUT_CYCLES)

    @classmethod
    def initialize(cls) -> LockoutState:
        return cls(count=0, lockout_count=0, last_failed_at=None, lockout_until=None)

    # --- Queries ---

    def is_threshold_reached(self, threshold: int) -> bool:
        return self.count >= threshold

    def is_expired_timed_lockout(self, now: datetime) -> bool:
        return self.is_timed() and self.is_expired(now)

    def is_timed(self) -> bool:
        return self.lockout_until is not None

    def is_expired(self, now: datetime) -> bool:
        if self.lockout_until is None:
            return False
        return now >= self.lockout_until

    # --- Behaviors ---

    def increment(self, now: datetime) -> LockoutState:
        return LockoutState(
            count=self.count + 1,
            lockout_count=self.lockout_count,
            last_failed_at=now,
            lockout_until=self.lockout_until,
        )

    def apply_lockout(
        self, tier_minutes: tuple[int, ...], now: datetime
    ) -> LockoutState:
        tier_index: int = min(self.lockout_count, len(tier_minutes) - 1)
        duration_minutes: int = tier_minutes[tier_index]
        lockout_until: datetime = now + timedelta(minutes=duration_minutes)
        return LockoutState(
            count=0,
            lockout_count=self.lockout_count + 1,
            last_failed_at=self.last_failed_at,
            lockout_until=lockout_until,
        )

    def reset(self) -> LockoutState:
        return LockoutState.initialize()

    def clear_expiry(self) -> LockoutState:
        return LockoutState(
            count=0,
            lockout_count=self.lockout_count,
            last_failed_at=self.last_failed_at,
            lockout_until=None,
        )

    def apply_indefinite_lockout(self) -> LockoutState:
        return LockoutState(
            count=self.count,
            lockout_count=self.lockout_count,
            last_failed_at=self.last_failed_at,
            lockout_until=None,
        )


@dataclass(frozen=True, slots=True)
class LockoutPolicy(ValueObject):
    _ABSOLUTE_MAX_THRESHOLD: ClassVar[int] = 100
    _ABSOLUTE_MAX_TIER_DURATION: ClassVar[int] = 1440

    threshold: int
    tier_minutes: tuple[int, ...]

    def __post_init__(self) -> None:
        guard_positive(self.threshold)
        guard_within_max(self.threshold, self._ABSOLUTE_MAX_THRESHOLD)
        guard_not_empty_collection(self.tier_minutes)
        guard_all_positive(self.tier_minutes)
        guard_all_within_max(self.tier_minutes, self._ABSOLUTE_MAX_TIER_DURATION)


@dataclass(frozen=True, slots=True)
class PasswordPolicy(ValueObject):
    _ABSOLUTE_MIN_LENGTH: ClassVar[int] = 8
    _ABSOLUTE_MAX_LENGTH: ClassVar[int] = 128
    _ABSOLUTE_MAX_HISTORY_DEPTH: ClassVar[int] = 24

    min_length: int
    max_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_digit: bool
    require_special: bool
    history_depth: int

    def __post_init__(self) -> None:
        guard_within_min(self.min_length, self._ABSOLUTE_MIN_LENGTH)
        guard_within_max(self.max_length, self._ABSOLUTE_MAX_LENGTH)
        guard_min_not_greater_than_max(self.min_length, self.max_length)
        guard_not_negative(self.history_depth)
        guard_within_max(self.history_depth, self._ABSOLUTE_MAX_HISTORY_DEPTH)

    def validate(self, raw_password: str) -> None:
        self._guard_not_empty(raw_password)
        self._guard_min_length(raw_password)
        self._guard_max_length(raw_password)
        self._guard_uppercase(raw_password)
        self._guard_lowercase(raw_password)
        self._guard_digit(raw_password)
        self._guard_special(raw_password)

    def _guard_not_empty(self, raw_password: str) -> None:
        if not raw_password:
            raise PasswordPolicyViolationError("Password must not be empty.")

    def _guard_min_length(self, raw_password: str) -> None:
        if len(raw_password) < self.min_length:
            raise PasswordPolicyViolationError(
                f"Password must be at least {self.min_length} characters."
            )

    def _guard_max_length(self, raw_password: str) -> None:
        if len(raw_password) > self.max_length:
            raise PasswordPolicyViolationError(
                f"Password must not exceed {self.max_length} characters."
            )

    def _guard_uppercase(self, raw_password: str) -> None:
        if self.require_uppercase and not any(
            character.isupper() for character in raw_password
        ):
            raise PasswordPolicyViolationError(
                "Password must contain at least one uppercase letter."
            )

    def _guard_lowercase(self, raw_password: str) -> None:
        if self.require_lowercase and not any(
            character.islower() for character in raw_password
        ):
            raise PasswordPolicyViolationError(
                "Password must contain at least one lowercase letter."
            )

    def _guard_digit(self, raw_password: str) -> None:
        if self.require_digit and not any(
            character.isdigit() for character in raw_password
        ):
            raise PasswordPolicyViolationError(
                "Password must contain at least one digit."
            )

    def _guard_special(self, raw_password: str) -> None:
        if self.require_special and not any(
            not character.isalnum() for character in raw_password
        ):
            raise PasswordPolicyViolationError(
                "Password must contain at least one special character."
            )
