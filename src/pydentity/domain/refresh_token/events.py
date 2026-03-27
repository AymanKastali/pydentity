from dataclasses import dataclass
from uuid import UUID

from pydentity.domain.base import DomainEvent

_NIL = UUID(int=0)


@dataclass(frozen=True, slots=True)
class RefreshTokenIssued(DomainEvent):
    token_id: UUID = _NIL
    account_id: UUID = _NIL
    family: UUID = _NIL


@dataclass(frozen=True, slots=True)
class RefreshTokenRevoked(DomainEvent):
    token_id: UUID = _NIL
    account_id: UUID = _NIL


@dataclass(frozen=True, slots=True)
class RefreshTokenFamilyRevoked(DomainEvent):
    account_id: UUID = _NIL
    family: UUID = _NIL
