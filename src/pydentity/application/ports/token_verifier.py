from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.application.models.access_token_claims import AccessTokenClaims


class TokenVerifierPort(ABC):
    @abstractmethod
    async def verify(self, token: str) -> AccessTokenClaims: ...
