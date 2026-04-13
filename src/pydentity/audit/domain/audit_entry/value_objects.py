from dataclasses import dataclass
from typing import ClassVar, Final
from uuid import UUID

from pydentity.shared_kernel.building_blocks import ValueObject
from pydentity.shared_kernel.guards import (
    guard_not_none,
    guard_within_max_length,
    guard_within_max_size,
)


@dataclass(frozen=True, slots=True)
class AuditEntryId(ValueObject):
    value: UUID

    def __post_init__(self) -> None:
        guard_not_none(self.value)


@dataclass(frozen=True, slots=True)
class EventPayload(ValueObject):
    _MAX_ENTRIES: ClassVar[Final[int]] = 50
    _MAX_KEY_LENGTH: ClassVar[Final[int]] = 100
    _MAX_VALUE_LENGTH: ClassVar[Final[int]] = 500

    entries: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        guard_within_max_size(self.entries, self._MAX_ENTRIES)
        for key, value in self.entries:
            guard_within_max_length(key, self._MAX_KEY_LENGTH)
            guard_within_max_length(value, self._MAX_VALUE_LENGTH)
