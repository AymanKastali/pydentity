from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class TokenClaims:
    sub: str
    email: str
    exp: datetime
    jti: str


class AccessTokenService(ABC):
    @abstractmethod
    def create_access_token(self, account_id: str, email: str) -> str: ...

    @abstractmethod
    def verify_access_token(self, token: str) -> TokenClaims: ...
