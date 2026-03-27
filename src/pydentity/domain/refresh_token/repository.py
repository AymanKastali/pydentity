from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.account.aggregate_id import AccountId
    from pydentity.domain.refresh_token.aggregate import RefreshToken
    from pydentity.domain.refresh_token.value_objects import TokenFamily


class RefreshTokenRepository(ABC):
    @abstractmethod
    async def find_by_token_hash(self, token_hash: str) -> RefreshToken | None: ...

    @abstractmethod
    async def save(self, refresh_token: RefreshToken) -> None: ...

    @abstractmethod
    async def revoke_all_by_family(self, family: TokenFamily) -> None: ...

    @abstractmethod
    async def revoke_all_by_account_id(self, account_id: AccountId) -> None: ...
