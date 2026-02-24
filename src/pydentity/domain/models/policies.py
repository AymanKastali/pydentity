from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydentity.domain.models.exceptions import PasswordPolicyViolationError

if TYPE_CHECKING:
    from datetime import timedelta


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
            raise ValueError("min_length must be at least 1")
        if self.history_size < 0:
            raise ValueError("history_size must be non-negative")

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
            raise PasswordPolicyViolationError("; ".join(violations))


@dataclass(frozen=True, slots=True)
class AccountLockoutPolicy:
    max_attempts: int
    lockout_duration: timedelta

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.lockout_duration.total_seconds() <= 0:
            raise ValueError("lockout_duration must be positive")


@dataclass(frozen=True, slots=True)
class TokenLifetimePolicy:
    access_token_ttl: timedelta
    refresh_token_ttl: timedelta
    session_absolute_ttl: timedelta

    def __post_init__(self) -> None:
        if self.access_token_ttl.total_seconds() <= 0:
            raise ValueError("access_token_ttl must be positive")
        if self.refresh_token_ttl.total_seconds() <= 0:
            raise ValueError("refresh_token_ttl must be positive")
        if self.session_absolute_ttl.total_seconds() <= 0:
            raise ValueError("session_absolute_ttl must be positive")
