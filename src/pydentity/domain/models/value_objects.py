from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydentity.domain.models.exceptions import (
    AccountLockedError,
    EmptyValueError,
    InvalidEmailAddressError,
    InvalidPolicyValueError,
    InvalidValueError,
    PasswordPolicyViolationError,
    ResetTokenExpiredError,
    ResetTokenInvalidError,
    ResetTokenNotIssuedError,
)

if TYPE_CHECKING:
    from datetime import datetime, timedelta

# --- Identity VOs ---


@dataclass(frozen=True, slots=True)
class UserId:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise EmptyValueError(field_name=self.__class__.__name__)


@dataclass(frozen=True, slots=True)
class SessionId:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise EmptyValueError(field_name=self.__class__.__name__)


@dataclass(frozen=True, slots=True)
class RoleId:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise EmptyValueError(field_name=self.__class__.__name__)


# --- Naming VOs ---


@dataclass(frozen=True, slots=True)
class DisplayName:
    value: str

    def __post_init__(self) -> None:
        stripped = self.value.strip()
        if not stripped:
            raise EmptyValueError(field_name=self.__class__.__name__)
        object.__setattr__(self, "value", stripped)


@dataclass(frozen=True, slots=True)
class RoleName:
    value: str

    def __post_init__(self) -> None:
        stripped = self.value.strip()
        if not stripped:
            raise EmptyValueError(field_name=self.__class__.__name__)
        object.__setattr__(self, "value", stripped)


@dataclass(frozen=True, slots=True)
class RoleDescription:
    value: str

    def __post_init__(self) -> None:
        stripped = self.value.strip()
        if not stripped:
            raise EmptyValueError(field_name=self.__class__.__name__)
        object.__setattr__(self, "value", stripped)


# --- Authorization VOs ---


@dataclass(frozen=True, slots=True)
class Permission:
    resource: str
    action: str

    def __post_init__(self) -> None:
        stripped_resource = self.resource.strip()
        stripped_action = self.action.strip()
        if not stripped_resource:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.resource")
        if not stripped_action:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.action")
        object.__setattr__(self, "resource", stripped_resource)
        object.__setattr__(self, "action", stripped_action)


# --- Auth VOs ---

_EMAIL_LOCAL_RE = re.compile(
    r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
)
_EMAIL_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


@dataclass(frozen=True, slots=True)
class EmailAddress:
    local_part: str
    domain: str

    def __post_init__(self) -> None:
        if not self.local_part:
            raise InvalidEmailAddressError(
                detail=f"invalid local part: {self.local_part!r}"
            )
        if not self.domain:
            raise InvalidEmailAddressError(detail=f"invalid domain: {self.domain!r}")
        if len(self.local_part) > 64:
            raise InvalidEmailAddressError(detail="local part exceeds 64 characters")
        if len(self.domain) > 255:
            raise InvalidEmailAddressError(detail="domain exceeds 255 characters")
        if not _EMAIL_LOCAL_RE.match(self.local_part):
            raise InvalidEmailAddressError(
                detail=f"invalid local part: {self.local_part!r}"
            )
        if not _EMAIL_DOMAIN_RE.match(self.domain):
            raise InvalidEmailAddressError(detail=f"invalid domain: {self.domain!r}")

    @property
    def full_address(self) -> str:
        return f"{self.local_part}@{self.domain}"

    def __str__(self) -> str:
        return self.full_address


@dataclass(frozen=True, slots=True)
class HashedPassword:
    value: bytes

    def __post_init__(self) -> None:
        if not self.value:
            raise EmptyValueError(field_name=self.__class__.__name__)


@dataclass(frozen=True, slots=True)
class HashedVerificationToken:
    value: bytes

    def __post_init__(self) -> None:
        if not self.value:
            raise EmptyValueError(field_name=self.__class__.__name__)


@dataclass(frozen=True, slots=True)
class HashedResetToken:
    value: bytes

    def __post_init__(self) -> None:
        if not self.value:
            raise EmptyValueError(field_name=self.__class__.__name__)


@dataclass(frozen=True, slots=True)
class HashedRefreshToken:
    value: bytes

    def __post_init__(self) -> None:
        if not self.value:
            raise EmptyValueError(field_name=self.__class__.__name__)

    def timing_safe_equals(self, other: HashedRefreshToken) -> bool:
        return hmac.compare_digest(self.value, other.value)


@dataclass(frozen=True, slots=True)
class FailedLoginAttempts:
    value: int

    def __post_init__(self) -> None:
        if self.value < 0:
            raise InvalidValueError(
                field_name=self.__class__.__name__,
                reason="must be non-negative",
            )

    def increment(self) -> FailedLoginAttempts:
        return FailedLoginAttempts(value=self.value + 1)

    def has_reached(self, max_attempts: int) -> bool:
        return self.value >= max_attempts


@dataclass(frozen=True, slots=True)
class LockoutExpiry:
    locked_until: datetime

    def is_active(self, now: datetime) -> bool:
        return now < self.locked_until


@dataclass(frozen=True, slots=True)
class SessionCreatedAt:
    created_at: datetime


@dataclass(frozen=True, slots=True)
class SessionLastRefresh:
    refreshed_at: datetime


@dataclass(frozen=True, slots=True)
class SessionExpiry:
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


@dataclass(frozen=True, slots=True)
class RefreshTokenFamily:
    family_id: str
    generation: int

    def __post_init__(self) -> None:
        if not self.family_id:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.family_id")
        if self.generation < 0:
            raise InvalidValueError(
                field_name=f"{self.__class__.__name__}.generation",
                reason="must be non-negative",
            )

    def next_generation(self) -> RefreshTokenFamily:
        return RefreshTokenFamily(
            family_id=self.family_id,
            generation=self.generation + 1,
        )


@dataclass(frozen=True, slots=True)
class EmailVerificationToken:
    token_hash: HashedVerificationToken
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def matches(self, candidate: HashedVerificationToken) -> bool:
        return self.token_hash == candidate


@dataclass(frozen=True, slots=True)
class PasswordResetToken:
    token_hash: HashedResetToken
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def matches(self, candidate: HashedResetToken) -> bool:
        return self.token_hash == candidate


# --- Composite VOs ---


@dataclass(frozen=True, slots=True)
class EmailVerification:
    is_verified: bool
    token: EmailVerificationToken | None

    def __post_init__(self) -> None:
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
class Credentials:
    password_hash: HashedPassword
    password_reset_token: PasswordResetToken | None
    password_history: tuple[HashedPassword, ...]

    def __post_init__(self) -> None:
        if not self.password_history:
            raise InvalidValueError(
                field_name="Credentials.password_history",
                reason="must contain at least one password",
            )

    def with_new_password(
        self, new_hash: HashedPassword, history_size: int
    ) -> Credentials:
        if history_size > 0:
            history = (*self.password_history, new_hash)[-history_size:]
        else:
            history = self.password_history
        return Credentials(
            password_hash=new_hash,
            password_reset_token=self.password_reset_token,
            password_history=history,
        )

    def with_reset_requested(self, token: PasswordResetToken) -> Credentials:
        return Credentials(
            password_hash=self.password_hash,
            password_reset_token=token,
            password_history=self.password_history,
        )

    def with_password_reset(
        self,
        token_hash: HashedResetToken,
        new_hash: HashedPassword,
        now: datetime,
        history_size: int,
    ) -> Credentials:
        if self.password_reset_token is None:
            raise ResetTokenNotIssuedError()
        if self.password_reset_token.is_expired(now):
            raise ResetTokenExpiredError()
        if not self.password_reset_token.matches(token_hash):
            raise ResetTokenInvalidError()

        updated = self.with_new_password(new_hash, history_size)
        return Credentials(
            password_hash=updated.password_hash,
            password_reset_token=None,
            password_history=updated.password_history,
        )


@dataclass(frozen=True, slots=True)
class LoginTracking:
    failed_login_attempts: FailedLoginAttempts
    lockout_expiry: LockoutExpiry | None

    def ensure_not_locked(self, now: datetime) -> None:
        if self.lockout_expiry is not None and self.lockout_expiry.is_active(now):
            raise AccountLockedError(locked_until=self.lockout_expiry.locked_until)

    def after_failed_attempt(
        self, policy: AccountLockoutPolicy, now: datetime
    ) -> tuple[LoginTracking, LockoutExpiry | None]:
        # Reset counter if previous lockout has expired — otherwise
        # the user is immediately re-locked on every attempt.
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
        return LoginTracking(
            failed_login_attempts=new_attempts,
            lockout_expiry=effective_lockout,
        ), new_lockout

    def after_successful_login(self) -> LoginTracking:
        return LoginTracking(
            failed_login_attempts=FailedLoginAttempts(0),
            lockout_expiry=None,
        )

    def reset(self) -> LoginTracking:
        return LoginTracking(
            failed_login_attempts=FailedLoginAttempts(0),
            lockout_expiry=None,
        )


# --- Token VO ---


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    issuer: str
    subject: UserId
    session_id: SessionId
    issued_at: datetime
    expires_at: datetime
    token_id: str
    permissions: frozenset[Permission]

    def __post_init__(self) -> None:
        if not self.issuer:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.issuer")
        if not self.token_id:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.token_id")
        if self.expires_at <= self.issued_at:
            raise InvalidValueError(
                field_name=f"{self.__class__.__name__}.expires_at",
                reason="must be after issued_at",
            )


# --- Policy VOs ---


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    min_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_digit: bool
    require_special: bool
    history_size: int

    def __post_init__(self) -> None:
        if self.min_length < 1:
            raise InvalidPolicyValueError(
                field_name="min_length", reason="must be at least 1"
            )
        if self.history_size < 0:
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
class AccountLockoutPolicy:
    max_attempts: int
    lockout_duration: timedelta

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise InvalidPolicyValueError(
                field_name="max_attempts", reason="must be at least 1"
            )
        if self.lockout_duration.total_seconds() <= 0:
            raise InvalidPolicyValueError(
                field_name="lockout_duration", reason="must be positive"
            )


@dataclass(frozen=True, slots=True)
class TokenLifetimePolicy:
    access_token_ttl: timedelta
    refresh_token_ttl: timedelta
    session_absolute_ttl: timedelta

    def __post_init__(self) -> None:
        if self.access_token_ttl.total_seconds() <= 0:
            raise InvalidPolicyValueError(
                field_name="access_token_ttl", reason="must be positive"
            )
        if self.refresh_token_ttl.total_seconds() <= 0:
            raise InvalidPolicyValueError(
                field_name="refresh_token_ttl", reason="must be positive"
            )
        if self.session_absolute_ttl.total_seconds() <= 0:
            raise InvalidPolicyValueError(
                field_name="session_absolute_ttl", reason="must be positive"
            )
