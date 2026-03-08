"""Fire-and-forget event publisher that pushes domain events to Redis pub/sub.

The use case returns immediately after PUBLISH — handler execution happens
asynchronously on the subscriber side.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydentity.adapters.outbound.events.serialization import serialize_event
from pydentity.application.ports.event_publisher import DomainEventPublisherPort

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from pydentity.domain.events.base import DomainEvent

_log = logging.getLogger("pydentity.events.publisher")


class RedisEventPublisher(DomainEventPublisherPort):
    def __init__(self, *, redis: Redis, channel: str) -> None:
        self._redis = redis
        self._channel = channel

    async def publish(self, events: list[DomainEvent]) -> None:
        if not events:
            return

        for event in events:
            payload = serialize_event(event)
            await self._redis.publish(self._channel, payload)
            _log.debug("published %s to %s", event.name, self._channel)
