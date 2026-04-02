from dataclasses import dataclass

from pydentity.authentication.domain.session.aggregate_id import SessionId
from pydentity.authentication.domain.session.value_objects import SessionEndReason
from pydentity.shared_kernel import AccountId, DomainEvent


@dataclass(frozen=True, slots=True)
class SessionStarted(DomainEvent):
    session_id: SessionId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class SessionEnded(DomainEvent):
    session_id: SessionId
    account_id: AccountId
    reason: SessionEndReason


@dataclass(frozen=True, slots=True)
class RefreshTokenRotated(DomainEvent):
    session_id: SessionId
    account_id: AccountId
