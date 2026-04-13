from dataclasses import dataclass
from enum import StrEnum, auto
from typing import ClassVar, Final
from uuid import UUID

from pydentity.shared_kernel.building_blocks import ValueObject
from pydentity.shared_kernel.guards import (
    guard_not_blank,
    guard_not_negative,
    guard_not_none,
    guard_within_max_length,
)


class Channel(StrEnum):
    EMAIL = auto()
    SMS = auto()


class ContentSensitivity(StrEnum):
    SENSITIVE = auto()
    STANDARD = auto()


class DeliveryStatus(StrEnum):
    PENDING = auto()
    SENT = auto()
    FAILED = auto()


@dataclass(frozen=True, slots=True)
class DeliveryRequestId(ValueObject):
    value: UUID

    def __post_init__(self) -> None:
        guard_not_none(self.value)


@dataclass(frozen=True, slots=True)
class Recipient(ValueObject):
    _MAX_ADDRESS_LENGTH: ClassVar[Final[int]] = 254

    address: str

    def __post_init__(self) -> None:
        guard_not_blank(self.address)
        guard_within_max_length(self.address, self._MAX_ADDRESS_LENGTH)


@dataclass(frozen=True, slots=True)
class MessageContent(ValueObject):
    _MAX_SUBJECT_LENGTH: ClassVar[Final[int]] = 200
    _MAX_BODY_LENGTH: ClassVar[Final[int]] = 50_000

    subject: str | None
    body: str

    def __post_init__(self) -> None:
        guard_not_blank(self.body)
        guard_within_max_length(self.body, self._MAX_BODY_LENGTH)
        if self.subject is not None:
            guard_within_max_length(self.subject, self._MAX_SUBJECT_LENGTH)


@dataclass(frozen=True, slots=True)
class AttemptCount(ValueObject):
    value: int

    def __post_init__(self) -> None:
        guard_not_negative(self.value)
