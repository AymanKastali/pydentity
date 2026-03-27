from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.account.aggregate import Account
    from pydentity.domain.account.aggregate_id import AccountId
    from pydentity.domain.account.value_objects import Email


class AccountRepository(ABC):
    @abstractmethod
    async def find_by_id(self, account_id: AccountId) -> Account | None: ...

    @abstractmethod
    async def find_by_email(self, email: Email) -> Account | None: ...

    @abstractmethod
    async def save(self, account: Account) -> None: ...
