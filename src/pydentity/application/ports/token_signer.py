from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.application.dtos.auth import AccessTokenClaims


class TokenSignerPort(ABC):
    @abstractmethod
    async def sign(self, claims: AccessTokenClaims) -> str: ...
