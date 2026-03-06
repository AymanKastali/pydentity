from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.ports.event_publisher import DomainEventPublisherPort

if TYPE_CHECKING:
    from pydentity.application.event_handlers.base import EventHandler
    from pydentity.domain.events.base import DomainEvent


class InMemoryEventPublisher(DomainEventPublisherPort):
    def __init__(
        self,
        handlers: dict[type[DomainEvent], list[EventHandler[DomainEvent]]],
    ) -> None:
        self._handlers = handlers

    async def publish(self, events: list[DomainEvent]) -> None:
        for event in events:
            for handler in self._handlers.get(type(event), []):
                await handler.handle(event)
