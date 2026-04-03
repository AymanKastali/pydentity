from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ValueObject:
    pass


@dataclass(frozen=True, slots=True)
class DomainEvent:
    occurred_at: datetime

    @property
    def name(self) -> str:
        return type(self).__name__


class DomainError(Exception):
    def __init__(self, message: str) -> None:
        self.message: str = message
        super().__init__(message)


class Entity[TId]:
    def __init__(self, entity_id: TId) -> None:
        self._id: TId = entity_id

    @property
    def id(self) -> TId:
        return self._id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Entity) or type(self) is not type(other):
            return False
        return bool(self._id == other._id)

    def __hash__(self) -> int:
        return hash(self._id)


class AggregateRoot[TId](Entity[TId]):
    def __init__(self, entity_id: TId) -> None:
        super().__init__(entity_id)
        self._events: list[DomainEvent] = []

    @property
    def events(self) -> list[DomainEvent]:
        return list(self._events)

    def clear_events(self) -> None:
        self._events.clear()

    def record_event(self, event: DomainEvent) -> None:
        self._events.append(event)
