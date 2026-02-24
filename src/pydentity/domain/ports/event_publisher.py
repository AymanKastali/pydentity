from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.events.base import DomainEvent


class DomainEventPublisherPort(ABC):
    @abstractmethod
    async def publish(self, events: list[DomainEvent]) -> None: ...
