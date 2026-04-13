from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from uuid import UUID

from pydentity.shared_kernel.building_blocks import ValueObject
from pydentity.shared_kernel.guards import guard_not_none, guard_positive


class SessionStatus(StrEnum):
    ACTIVE = auto()
    REVOKED = auto()


class SessionRevocationReason(StrEnum):
    LOGOUT = auto()
    EXPIRED = auto()
    FORCED = auto()
    COMPROMISE = auto()


@dataclass(frozen=True, slots=True)
class SessionId(ValueObject):
    value: UUID

    def __post_init__(self) -> None:
        guard_not_none(self.value)


@dataclass(frozen=True, slots=True)
class SessionPolicy(ValueObject):
    ttl_seconds: int

    def __post_init__(self) -> None:
        guard_positive(self.ttl_seconds)


@dataclass(frozen=True, slots=True)
class SessionExpiry(ValueObject):
    value: datetime
