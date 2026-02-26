from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import HashedPassword


class PasswordHasherPort(ABC):
    @abstractmethod
    async def hash(self, plain: str) -> HashedPassword: ...

    @abstractmethod
    async def verify(self, plain: str, hashed: HashedPassword) -> bool: ...
