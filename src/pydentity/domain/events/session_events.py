from __future__ import annotations

from dataclasses import dataclass

from pydentity.domain.events.base import DomainEvent


@dataclass(frozen=True, slots=True)
class SessionEstablished(DomainEvent):
    session_id: str
    user_id: str


@dataclass(frozen=True, slots=True)
class RefreshTokenRotated(DomainEvent):
    session_id: str


@dataclass(frozen=True, slots=True)
class RefreshTokenReused(DomainEvent):
    session_id: str
    user_id: str


@dataclass(frozen=True, slots=True)
class SessionTerminated(DomainEvent):
    session_id: str
