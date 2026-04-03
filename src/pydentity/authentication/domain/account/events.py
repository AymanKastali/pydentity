from dataclasses import dataclass

from pydentity.authentication.domain.account.value_objects import (
    LockReason,
    UnlockReason,
)
from pydentity.shared_kernel import AccountId, DomainEvent


@dataclass(frozen=True, slots=True)
class AccountRegistered(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class EmailVerificationRequested(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class EmailVerified(DomainEvent):
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


@dataclass(frozen=True, slots=True)
class PasswordChanged(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class TOTPSecretAdded(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class TOTPSecretRemoved(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class RecoveryCodesGenerated(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class RecoveryCodeConsumed(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class MFAEnabled(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class MFADisabled(DomainEvent):
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class PasswordResetCompleted(DomainEvent):
    account_id: AccountId
