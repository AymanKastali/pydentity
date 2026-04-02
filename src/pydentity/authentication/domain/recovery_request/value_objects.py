from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from typing import ClassVar

from pydentity.authentication.domain.recovery_request.errors import (
    RecoveryRequestAlreadyCompletedError,
    RecoveryRequestAlreadyExpiredError,
    RecoveryRequestNotPendingError,
    RecoveryRequestNotVerifiedError,
    RecoveryTokenExpiredError,
)
from pydentity.shared_kernel import (
    ValueObject,
    guard_not_empty,
    guard_within_max_length,
)


class RecoveryRequestStatus(StrEnum):
    PENDING = auto()
    VERIFIED = auto()
    COMPLETED = auto()
    EXPIRED = auto()

    # --- Queries ---

    @property
    def is_pending(self) -> bool:
        return self is RecoveryRequestStatus.PENDING

    @property
    def is_verified(self) -> bool:
        return self is RecoveryRequestStatus.VERIFIED

    @property
    def is_completed(self) -> bool:
        return self is RecoveryRequestStatus.COMPLETED

    @property
    def is_expired(self) -> bool:
        return self is RecoveryRequestStatus.EXPIRED

    # --- Guards ---

    def guard_is_pending(self) -> None:
        if not self.is_pending:
            raise RecoveryRequestNotPendingError()

    def guard_is_verified(self) -> None:
        if not self.is_verified:
            raise RecoveryRequestNotVerifiedError()

    def guard_not_completed(self) -> None:
        if self.is_completed:
            raise RecoveryRequestAlreadyCompletedError()

    def guard_not_expired(self) -> None:
        if self.is_expired:
            raise RecoveryRequestAlreadyExpiredError()


@dataclass(frozen=True, slots=True)
class RecoveryToken(ValueObject):
    _MAX_HASH_LENGTH: ClassVar[int] = 256

    token_hash: str
    expires_at: datetime

    def __post_init__(self) -> None:
        guard_not_empty(self.token_hash)
        guard_within_max_length(self.token_hash, self._MAX_HASH_LENGTH)

    # --- Queries ---

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    # --- Guards ---

    def guard_not_expired(self, now: datetime) -> None:
        if self.is_expired(now):
            raise RecoveryTokenExpiredError()
