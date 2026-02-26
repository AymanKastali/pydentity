from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydentity.domain.events.base import DomainEvent

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class UserRegistered(DomainEvent):
    user_id: str
    email: str
    display_name: str


@dataclass(frozen=True, slots=True)
class EmailVerified(DomainEvent):
    user_id: str


@dataclass(frozen=True, slots=True)
class VerificationTokenReissued(DomainEvent):
    user_id: str


@dataclass(frozen=True, slots=True)
class UserEmailChanged(DomainEvent):
    user_id: str
    old_email: str
    new_email: str


@dataclass(frozen=True, slots=True)
class PasswordChanged(DomainEvent):
    user_id: str


@dataclass(frozen=True, slots=True)
class PasswordResetRequested(DomainEvent):
    user_id: str


@dataclass(frozen=True, slots=True)
class PasswordReset(DomainEvent):
    user_id: str


@dataclass(frozen=True, slots=True)
class LoginFailed(DomainEvent):
    user_id: str
    failed_attempts: int


@dataclass(frozen=True, slots=True)
class LoginSucceeded(DomainEvent):
    user_id: str


@dataclass(frozen=True, slots=True)
class AccountLocked(DomainEvent):
    user_id: str
    locked_until: datetime


@dataclass(frozen=True, slots=True)
class UserSuspended(DomainEvent):
    user_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class UserReactivated(DomainEvent):
    user_id: str


@dataclass(frozen=True, slots=True)
class UserDeactivated(DomainEvent):
    user_id: str


@dataclass(frozen=True, slots=True)
class RoleAssignedToUser(DomainEvent):
    user_id: str
    role_id: str


@dataclass(frozen=True, slots=True)
class RoleRevokedFromUser(DomainEvent):
    user_id: str
    role_id: str
