from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


class IdGenerator(ABC):
    @abstractmethod
    def generate(self) -> UUID: ...
