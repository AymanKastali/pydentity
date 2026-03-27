from dataclasses import dataclass
from uuid import UUID

from pydentity.domain.base import DomainEvent

_NIL = UUID(int=0)


@dataclass(frozen=True, slots=True)
class AccountRegistered(DomainEvent):
    account_id: UUID = _NIL
    email: str = ""


@dataclass(frozen=True, slots=True)
class AccountEmailVerified(DomainEvent):
    account_id: UUID = _NIL


@dataclass(frozen=True, slots=True)
class AccountPasswordChanged(DomainEvent):
    account_id: UUID = _NIL


@dataclass(frozen=True, slots=True)
class AccountSuspended(DomainEvent):
    account_id: UUID = _NIL
