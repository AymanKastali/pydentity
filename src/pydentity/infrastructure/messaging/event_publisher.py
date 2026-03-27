import logging
from typing import TYPE_CHECKING, Any

from pydentity.application.services.event_publisher import EventPublisher

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.domain.base import DomainEvent

logger = logging.getLogger(__name__)


class InProcessEventPublisher(EventPublisher):
    def __init__(self) -> None:
        self._handlers: dict[type[DomainEvent], list[Callable[..., Any]]] = {}

    def register(
        self,
        event_type: type[DomainEvent],
        handler: Callable[..., Any],
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def publish(self, events: list[DomainEvent]) -> None:
        for event in events:
            handlers = self._handlers.get(type(event), [])
            for handler in handlers:
                handler(event)
            if not handlers:
                logger.info(
                    "No handler for %s: %s",
                    type(event).__name__,
                    event,
                )
