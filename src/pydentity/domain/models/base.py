from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.events.base import DomainEvent


class Entity[TId]:
    _id: TId

    @property
    def id(self) -> TId:
        return self._id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)


class AggregateRoot[TId](Entity[TId]):
    def __init__(self) -> None:
        self._events: list[DomainEvent] = []

    def _record_event(self, event: DomainEvent) -> None:
        self._events.append(event)

    def collect_events(self) -> list[DomainEvent]:
        return list(self._events)

    def clear_events(self) -> None:
        self._events.clear()
