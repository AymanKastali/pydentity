from dataclasses import dataclass

from pydentity.authentication.domain.recovery_request.aggregate_id import (
    RecoveryRequestId,
)
from pydentity.shared_kernel import AccountId, DomainEvent


@dataclass(frozen=True, slots=True)
class PasswordResetRequested(DomainEvent):
    request_id: RecoveryRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class RecoveryTokenIssued(DomainEvent):
    request_id: RecoveryRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class RecoveryTokenVerified(DomainEvent):
    request_id: RecoveryRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class RecoveryRequestCompleted(DomainEvent):
    request_id: RecoveryRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class PasswordResetExpired(DomainEvent):
    request_id: RecoveryRequestId
    account_id: AccountId
