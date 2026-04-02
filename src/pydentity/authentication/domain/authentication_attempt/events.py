from dataclasses import dataclass

from pydentity.authentication.domain.authentication_attempt.aggregate_id import (
    AuthAttemptId,
)
from pydentity.authentication.domain.authentication_attempt.value_objects import (
    AuthenticationFactor,
)
from pydentity.shared_kernel import AccountId, DomainEvent


@dataclass(frozen=True, slots=True)
class AuthenticationSucceeded(DomainEvent):
    attempt_id: AuthAttemptId
    account_id: AccountId
    factors_used: tuple[AuthenticationFactor, ...]


@dataclass(frozen=True, slots=True)
class AuthenticationFailed(DomainEvent):
    attempt_id: AuthAttemptId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class VerificationCodeGenerated(DomainEvent):
    attempt_id: AuthAttemptId
    account_id: AccountId
