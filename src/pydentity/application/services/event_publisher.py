from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.base import DomainEvent


class EventPublisher(ABC):
    @abstractmethod
    def publish(self, events: list[DomainEvent]) -> None: ...
