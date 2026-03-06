from __future__ import annotations

from abc import ABC, abstractmethod


class EventHandler[T](ABC):
    @abstractmethod
    async def handle(self, event: T) -> None: ...
