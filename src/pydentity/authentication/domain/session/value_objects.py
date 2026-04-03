from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from typing import ClassVar

from pydentity.authentication.domain.session.errors import (
    RefreshTokenExpiredError,
    RefreshTokenRevokedError,
    SessionAlreadyEndedError,
)
from pydentity.shared_kernel import (
    ValueObject,
    guard_not_empty,
    guard_within_max_length,
)


class SessionStatus(StrEnum):
    ACTIVE = auto()
    ENDED = auto()

    # --- Queries ---

    @property
    def is_active(self) -> bool:
        return self is SessionStatus.ACTIVE

    @property
    def is_ended(self) -> bool:
        return self is SessionStatus.ENDED

    # --- Guards ---

    def guard_is_active(self) -> None:
        if not self.is_active:
            raise SessionAlreadyEndedError()


class SessionEndReason(StrEnum):
    LOGOUT = auto()
    IDLE_TIMEOUT = auto()
    ABSOLUTE_TIMEOUT = auto()
    FORCED = auto()
    COMPROMISE = auto()


@dataclass(frozen=True, slots=True)
class RefreshToken(ValueObject):
    _MAX_HASH_LENGTH: ClassVar[int] = 256

    token_hash: str
    expires_at: datetime
    is_revoked: bool

    def __post_init__(self) -> None:
        guard_not_empty(self.token_hash)
        guard_within_max_length(self.token_hash, self._MAX_HASH_LENGTH)

    # --- Queries ---

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    # --- Guards ---

    def guard_not_expired(self, now: datetime) -> None:
        if self.is_expired(now):
            raise RefreshTokenExpiredError()

    def guard_not_revoked(self) -> None:
        if self.is_revoked:
            raise RefreshTokenRevokedError()
