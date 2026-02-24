from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import HashedRefreshToken


class TokenHasherPort(ABC):
    @abstractmethod
    def hash(self, raw_token: str) -> HashedRefreshToken: ...

    @abstractmethod
    def generate_raw_token(self) -> str: ...
