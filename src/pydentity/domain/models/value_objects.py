from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Self

from pydentity.domain.exceptions import (
    AccountLockedError,
    InvalidPolicyValueError,
    InvalidValueError,
    PasswordPolicyViolationError,
)
from pydentity.domain.guards import verify_params
from pydentity.domain.models.base import ValueObject

# --- Identity VOs ---


@dataclass(frozen=True, slots=True)
class UserId(ValueObject):
    value: str

    def __post_init__(self) -> None:
        verify_params(value=(self.value, str))


@dataclass(frozen=True, slots=True)
class SessionId(ValueObject):
    value: str

    def __post_init__(self) -> None:
        verify_params(value=(self.value, str))


@dataclass(frozen=True, slots=True)
class DeviceId(ValueObject):
    value: str

    def __post_init__(self) -> None:
        verify_params(value=(self.value, str))


# --- Naming VOs ---


@dataclass(frozen=True, slots=True)
class RoleName(ValueObject):
    value: str

    def __post_init__(self) -> None:
        verify_params(value=(self.value, str))

    @classmethod
    def create(cls, raw: str) -> Self:
        return cls(value=raw.strip())


@dataclass(frozen=True, slots=True)
class RoleDescription(ValueObject):
    value: str

    def __post_init__(self) -> None:
        verify_params(value=(self.value, str))

    @classmethod
    def create(cls, raw: str) -> Self:
        return cls(value=raw.strip())


@dataclass(frozen=True, slots=True)
class DeviceName(ValueObject):
    value: str

    def __post_init__(self) -> None:
        verify_params(value=(self.value, str))

    @classmethod
    def create(cls, raw: str) -> Self:
        return cls(value=raw.strip())


@dataclass(frozen=True, slots=True)
class DeviceLastActive(ValueObject):
    last_active_at: datetime

    def __post_init__(self) -> None:
        verify_params(last_active_at=(self.last_active_at, datetime))

    def bump(self, now: datetime) -> Self:
        return type(self)(last_active_at=now)


# --- Authorization VOs ---


@dataclass(frozen=True, slots=True)
class Permission(ValueObject):
    value: str

    def __post_init__(self) -> None:
        verify_params(value=(self.value, str))
        if not self.value or ":" not in self.value:
            raise InvalidValueError(
                field_name="Permission",
                reason="must be non-empty and contain ':'",
            )

    @classmethod
    def from_resource_action(cls, resource: str, action: str) -> Self:
        return cls(value=f"{resource}:{action}")


# --- Auth VOs ---


@dataclass(frozen=True, slots=True)
class EmailAddress(ValueObject):
    local_part: str
    domain: str

    def __post_init__(self) -> None:
        verify_params(local_part=(self.local_part, str), domain=(self.domain, str))

    @property
    def address(self) -> str:
        return f"{self.local_part}@{self.domain}"

    def __str__(self) -> str:
        return self.address


@dataclass(frozen=True, slots=True)
class HashedPassword(ValueObject):
    value: bytes

    def __post_init__(self) -> None:
        verify_params(value=(self.value, bytes))


@dataclass(frozen=True, slots=True)
class HashedVerificationToken(ValueObject):
    value: bytes

    def __post_init__(self) -> None:
        verify_params(value=(self.value, bytes))


@dataclass(frozen=True, slots=True)
class HashedResetToken(ValueObject):
    value: bytes

    def __post_init__(self) -> None:
        verify_params(value=(self.value, bytes))


@dataclass(frozen=True, slots=True)
class HashedRefreshToken(ValueObject):
    value: bytes

    def __post_init__(self) -> None:
        verify_params(value=(self.value, bytes))


@dataclass(frozen=True, slots=True)
class FailedLoginAttempts(ValueObject):
    value: int

    def __post_init__(self) -> None:
        verify_params(value=(self.value, int))
        if self.value < 0:
            raise InvalidValueError(
                field_name=self.__class__.__name__,
                reason="must be non-negative",
            )

    def increment(self) -> Self:
        return type(self)(value=self.value + 1)

    def has_reached(self, max_attempts: int) -> bool:
        return self.value >= max_attempts


@dataclass(frozen=True, slots=True)
class LockoutExpiry(ValueObject):
    locked_until: datetime

    def __post_init__(self) -> None:
        verify_params(locked_until=(self.locked_until, datetime))

    def is_active(self, now: datetime) -> bool:
        return now < self.locked_until


@dataclass(frozen=True, slots=True)
class SessionCreatedAt(ValueObject):
    created_at: datetime

    def __post_init__(self) -> None:
        verify_params(created_at=(self.created_at, datetime))


@dataclass(frozen=True, slots=True)
class SessionLastRefresh(ValueObject):
    refreshed_at: datetime

    def __post_init__(self) -> None:
        verify_params(refreshed_at=(self.refreshed_at, datetime))


@dataclass(frozen=True, slots=True)
class SessionExpiry(ValueObject):
    expires_at: datetime

    def __post_init__(self) -> None:
        verify_params(expires_at=(self.expires_at, datetime))

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


@dataclass(frozen=True, slots=True)
class RefreshTokenFamily(ValueObject):
    family_id: str
    generation: int

    def __post_init__(self) -> None:
        verify_params(
            family_id=(self.family_id, str), generation=(self.generation, int)
        )
        self._ensure_valid_generation(self.generation)

    @classmethod
    def _ensure_valid_generation(cls, generation: int) -> None:
        if generation < 0:
            raise InvalidValueError(
                field_name=f"{cls.__name__}.generation",
                reason="must be non-negative",
            )

    def next_generation(self) -> Self:
        return type(self)(
            family_id=self.family_id,
            generation=self.generation + 1,
        )


@dataclass(frozen=True, slots=True)
class EmailVerificationToken(ValueObject):
    token_hash: HashedVerificationToken
    expires_at: datetime

    def __post_init__(self) -> None:
        verify_params(token_hash=(self.token_hash, HashedVerificationToken))

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


@dataclass(frozen=True, slots=True)
class PasswordResetToken(ValueObject):
    token_hash: HashedResetToken
    expires_at: datetime

    def __post_init__(self) -> None:
        verify_params(token_hash=(self.token_hash, HashedResetToken))

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


# --- Composite VOs ---


@dataclass(frozen=True, slots=True)
class EmailVerification(ValueObject):
    is_verified: bool
    token: EmailVerificationToken | None

    def __post_init__(self) -> None:
        verify_params(token=(self.token, EmailVerificationToken | None))
        self._ensure_consistent_state()

    def _ensure_consistent_state(self) -> None:
        if self.is_verified and self.token is not None:
            raise InvalidValueError(
                field_name="EmailVerification",
                reason="verified email must not carry a pending token",
            )
        if not self.is_verified and self.token is None:
            raise InvalidValueError(
                field_name="EmailVerification",
                reason="unverified email must have a verification token",
            )


@dataclass(frozen=True, slots=True)
class Credentials(ValueObject):
    password_hash: HashedPassword
    password_reset_token: PasswordResetToken | None
    password_history: tuple[HashedPassword, ...]

    def __post_init__(self) -> None:
        verify_params(
            password_hash=(self.password_hash, HashedPassword),
            password_reset_token=(self.password_reset_token, PasswordResetToken | None),
            password_history=(self.password_history, tuple[HashedPassword, ...]),
        )
        if not self.password_history:
            raise InvalidValueError(
                field_name="Credentials.password_history",
                reason="must contain at least one password",
            )

    def with_new_password(self, new_hash: HashedPassword, history_size: int) -> Self:
        if history_size > 0:
            history = (*self.password_history, new_hash)[-history_size:]
        else:
            history = self.password_history
        return type(self)(
            password_hash=new_hash,
            password_reset_token=self.password_reset_token,
            password_history=history,
        )

    def with_reset_requested(self, token: PasswordResetToken) -> Self:
        return type(self)(
            password_hash=self.password_hash,
            password_reset_token=token,
            password_history=self.password_history,
        )

    def with_password_reset(self, new_hash: HashedPassword, history_size: int) -> Self:
        updated = self.with_new_password(new_hash, history_size)
        return type(self)(
            password_hash=updated.password_hash,
            password_reset_token=None,
            password_history=updated.password_history,
        )


@dataclass(frozen=True, slots=True)
class LoginTracking(ValueObject):
    failed_login_attempts: FailedLoginAttempts
    lockout_expiry: LockoutExpiry | None

    def __post_init__(self) -> None:
        verify_params(
            failed_login_attempts=(self.failed_login_attempts, FailedLoginAttempts),
            lockout_expiry=(self.lockout_expiry, LockoutExpiry | None),
        )

    def ensure_not_locked(self, now: datetime) -> None:
        if self.lockout_expiry is not None and self.lockout_expiry.is_active(now):
            raise AccountLockedError(locked_until=self.lockout_expiry.locked_until)

    def after_failed_attempt(
        self, policy: AccountLockoutPolicy, now: datetime
    ) -> tuple[Self, LockoutExpiry | None]:
        previous_lockout_expired = (
            self.lockout_expiry is not None and not self.lockout_expiry.is_active(now)
        )
        base_attempts = (
            FailedLoginAttempts(0)
            if previous_lockout_expired
            else self.failed_login_attempts
        )
        new_attempts = base_attempts.increment()
        new_lockout = (
            LockoutExpiry(locked_until=now + policy.lockout_duration)
            if new_attempts.has_reached(policy.max_attempts)
            else None
        )
        effective_lockout = (
            new_lockout if new_lockout is not None else self.lockout_expiry
        )
        return type(self)(
            failed_login_attempts=new_attempts,
            lockout_expiry=effective_lockout,
        ), new_lockout

    def after_successful_login(self) -> Self:
        return self._cleared()

    def reset(self) -> Self:
        return self._cleared()

    def _cleared(self) -> Self:
        return type(self)(
            failed_login_attempts=FailedLoginAttempts(0),
            lockout_expiry=None,
        )


@dataclass(frozen=True, slots=True)
class DeviceFingerprint(ValueObject):
    value: str

    def __post_init__(self) -> None:
        verify_params(value=(self.value, str))


# --- Policy VOs ---


@dataclass(frozen=True, slots=True)
class PasswordPolicy(ValueObject):
    min_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_digit: bool
    require_special: bool
    history_size: int

    def __post_init__(self) -> None:
        verify_params(
            min_length=(self.min_length, int),
            require_uppercase=(self.require_uppercase, bool),
            require_lowercase=(self.require_lowercase, bool),
            require_digit=(self.require_digit, bool),
            require_special=(self.require_special, bool),
            history_size=(self.history_size, int),
        )
        self._ensure_valid_min_length(self.min_length)
        self._ensure_valid_history_size(self.history_size)

    @classmethod
    def _ensure_valid_min_length(cls, min_length: int) -> None:
        if min_length < 1:
            raise InvalidPolicyValueError(
                field_name="min_length", reason="must be at least 1"
            )

    @classmethod
    def _ensure_valid_history_size(cls, history_size: int) -> None:
        if history_size < 0:
            raise InvalidPolicyValueError(
                field_name="history_size", reason="must be non-negative"
            )

    def validate(self, plain_password: str) -> None:
        violations: list[str] = []

        if len(plain_password) < self.min_length:
            violations.append(f"Password must be at least {self.min_length} characters")
        if self.require_uppercase and not any(c.isupper() for c in plain_password):
            violations.append("Password must contain at least one uppercase letter")
        if self.require_lowercase and not any(c.islower() for c in plain_password):
            violations.append("Password must contain at least one lowercase letter")
        if self.require_digit and not any(c.isdigit() for c in plain_password):
            violations.append("Password must contain at least one digit")
        if self.require_special and not any(not c.isalnum() for c in plain_password):
            violations.append("Password must contain at least one special character")

        if violations:
            raise PasswordPolicyViolationError(violations=violations)


@dataclass(frozen=True, slots=True)
class AccountLockoutPolicy(ValueObject):
    max_attempts: int
    lockout_duration: timedelta

    def __post_init__(self) -> None:
        verify_params(
            max_attempts=(self.max_attempts, int),
            lockout_duration=(self.lockout_duration, timedelta),
        )
        self._ensure_valid_max_attempts(self.max_attempts)
        self._ensure_valid_lockout_duration(self.lockout_duration)

    @classmethod
    def _ensure_valid_max_attempts(cls, max_attempts: int) -> None:
        if max_attempts < 1:
            raise InvalidPolicyValueError(
                field_name="max_attempts", reason="must be at least 1"
            )

    @classmethod
    def _ensure_valid_lockout_duration(cls, lockout_duration: timedelta) -> None:
        if lockout_duration.total_seconds() <= 0:
            raise InvalidPolicyValueError(
                field_name="lockout_duration", reason="must be positive"
            )


@dataclass(frozen=True, slots=True)
class TokenLifetimePolicy(ValueObject):
    access_token_ttl: timedelta
    refresh_token_ttl: timedelta
    session_absolute_ttl: timedelta

    def __post_init__(self) -> None:
        verify_params(
            access_token_ttl=(self.access_token_ttl, timedelta),
            refresh_token_ttl=(self.refresh_token_ttl, timedelta),
            session_absolute_ttl=(self.session_absolute_ttl, timedelta),
        )
        self._ensure_positive_ttl("access_token_ttl", self.access_token_ttl)
        self._ensure_positive_ttl("refresh_token_ttl", self.refresh_token_ttl)
        self._ensure_positive_ttl("session_absolute_ttl", self.session_absolute_ttl)

    @classmethod
    def _ensure_positive_ttl(cls, field_name: str, ttl: timedelta) -> None:
        if ttl.total_seconds() <= 0:
            raise InvalidPolicyValueError(
                field_name=field_name, reason="must be positive"
            )


@dataclass(frozen=True, slots=True)
class EmailVerificationPolicy(ValueObject):
    required_on_registration: bool
    required_on_email_change: bool
    token_ttl: timedelta

    def __post_init__(self) -> None:
        verify_params(
            required_on_registration=(self.required_on_registration, bool),
            required_on_email_change=(self.required_on_email_change, bool),
            token_ttl=(self.token_ttl, timedelta),
        )
        if self.token_ttl.total_seconds() <= 0:
            raise InvalidPolicyValueError(
                field_name="token_ttl", reason="must be positive"
            )


@dataclass(frozen=True, slots=True)
class DevicePolicy(ValueObject):
    max_devices_per_user: int

    def __post_init__(self) -> None:
        verify_params(max_devices_per_user=(self.max_devices_per_user, int))
        if self.max_devices_per_user < 1:
            raise InvalidPolicyValueError(
                field_name="max_devices_per_user", reason="must be at least 1"
            )
