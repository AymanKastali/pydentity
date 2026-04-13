from dataclasses import dataclass

from pydentity.authentication.domain.account.value_objects import (
    Email,
    FailedAttemptCount,
    LockReason,
    UnlockReason,
)
from pydentity.shared_kernel.building_blocks import DomainEvent
from pydentity.shared_kernel.value_objects import AccountId


@dataclass(frozen=True, slots=True)
class AccountRegistered(DomainEvent):
    account_id: AccountId
    email: Email


@dataclass(frozen=True, slots=True)
class LoginSucceeded(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class LoginFailed(DomainEvent):
    account_id: AccountId
    failed_attempt_count: FailedAttemptCount


@dataclass(frozen=True, slots=True)
class EmailVerified(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class EmailChanged(DomainEvent):
    account_id: AccountId
    old_email: Email
    new_email: Email


@dataclass(frozen=True, slots=True)
class PasswordChanged(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class AccountLocked(DomainEvent):
    account_id: AccountId
    reason: LockReason


@dataclass(frozen=True, slots=True)
class AccountUnlocked(DomainEvent):
    account_id: AccountId
    reason: UnlockReason


@dataclass(frozen=True, slots=True)
class AccountSuspended(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class AccountClosed(DomainEvent):
    account_id: AccountId
