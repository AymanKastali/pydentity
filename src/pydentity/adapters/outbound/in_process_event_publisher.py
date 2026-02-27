from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydentity.domain.ports.event_publisher import DomainEventPublisherPort

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from pydentity.domain.events.base import DomainEvent


class InProcessEventPublisher(DomainEventPublisherPort):
    def __init__(self) -> None:
        self._handlers: dict[
            type[DomainEvent], list[Callable[[Any], Awaitable[None]]]
        ] = {}

    def subscribe(
        self,
        event_type: type[DomainEvent],
        handler: Callable[[Any], Awaitable[None]],
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    async def publish(self, events: list[DomainEvent]) -> None:
        for event in events:
            for handler in self._handlers.get(type(event), []):
                await handler(event)
