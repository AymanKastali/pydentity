from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.account.aggregate_id import AccountId
    from pydentity.domain.refresh_token.aggregate import RefreshToken


class RefreshTokenFactory(ABC):
    @abstractmethod
    def issue(self, account_id: AccountId) -> tuple[str, RefreshToken]: ...

    @abstractmethod
    def rotate(self, old_token: RefreshToken) -> tuple[str, RefreshToken]: ...
