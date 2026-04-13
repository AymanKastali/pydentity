from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ValueObject:
    pass


@dataclass(frozen=True, slots=True)
class EventName(ValueObject):
    value: str


@dataclass(frozen=True, slots=True)
class DomainEvent(ValueObject):
    @property
    def name(self) -> EventName:
        return EventName(type(self).__name__)


class DomainError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self._message = message

    @property
    def message(self) -> str:
        return self._message


class Entity[TId]:
    def __init__(self, entity_id: TId, /) -> None:
        self._id: TId = entity_id

    @property
    def id(self) -> TId:
        return self._id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)


class AggregateRoot[TId](Entity[TId]):
    def __init__(self, entity_id: TId, /) -> None:
        super().__init__(entity_id)
        self._events: list[DomainEvent] = []

    def record_event(self, event: DomainEvent) -> None:
        self._events.append(event)

    def clear_events(self) -> None:
        self._events.clear()

    @property
    def events(self) -> list[DomainEvent]:
        return list(self._events)
