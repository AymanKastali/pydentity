from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.events.base import DomainEvent


class Entity:
    pass


class AggregateRoot(Entity):
    _events: list[DomainEvent]

    def _record_event(self, event: DomainEvent) -> None:
        self._events.append(event)

    def collect_events(self) -> list[DomainEvent]:
        events = list(self._events)
        self._events.clear()
        return events
