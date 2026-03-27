from typing import TYPE_CHECKING

from pydentity.domain.base.entity import Entity

if TYPE_CHECKING:
    from uuid import UUID

    from pydentity.domain.base.domain_event import DomainEvent


class AggregateRoot(Entity):
    def __init__(self, entity_id: UUID) -> None:
        super().__init__(entity_id)
        self._events: list[DomainEvent] = []

    def _record_event(self, event: DomainEvent) -> None:
        self._events.append(event)

    def collect_events(self) -> list[DomainEvent]:
        events = list(self._events)
        self._events.clear()
        return events
