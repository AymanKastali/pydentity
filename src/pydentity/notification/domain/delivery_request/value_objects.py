from dataclasses import dataclass
from enum import StrEnum, auto
from typing import ClassVar

from pydentity.notification.domain.delivery_request.errors import (
    DeliveryRequestAlreadyFailedError,
    DeliveryRequestAlreadySentError,
)
from pydentity.shared_kernel import (
    ValueObject,
    guard_not_empty,
    guard_within_max_length,
)


class Channel(StrEnum):
    EMAIL = auto()
    SMS = auto()


class DeliveryStatus(StrEnum):
    PENDING = auto()
    SENT = auto()
    FAILED = auto()

    # --- Queries ---

    @property
    def is_pending(self) -> bool:
        return self is DeliveryStatus.PENDING

    @property
    def is_sent(self) -> bool:
        return self is DeliveryStatus.SENT

    @property
    def is_failed(self) -> bool:
        return self is DeliveryStatus.FAILED

    # --- Guards ---

    def guard_not_sent(self) -> None:
        if self.is_sent:
            raise DeliveryRequestAlreadySentError()

    def guard_not_failed(self) -> None:
        if self.is_failed:
            raise DeliveryRequestAlreadyFailedError()


@dataclass(frozen=True, slots=True)
class Recipient(ValueObject):
    _MAX_LENGTH: ClassVar[int] = 254

    address: str

    def __post_init__(self) -> None:
        guard_not_empty(self.address)
        guard_within_max_length(self.address, self._MAX_LENGTH)


@dataclass(frozen=True, slots=True)
class MessageContent(ValueObject):
    _MAX_SUBJECT_LENGTH: ClassVar[int] = 200
    _MAX_BODY_LENGTH: ClassVar[int] = 50_000

    subject: str | None
    body: str

    def __post_init__(self) -> None:
        guard_not_empty(self.body)
        guard_within_max_length(self.body, self._MAX_BODY_LENGTH)
        if self.subject is not None:
            guard_within_max_length(self.subject, self._MAX_SUBJECT_LENGTH)
