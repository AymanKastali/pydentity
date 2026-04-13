from abc import ABC, abstractmethod

from pydentity.authentication.domain.account.aggregate import Account
from pydentity.authentication.domain.account.value_objects import Email
from pydentity.shared_kernel.value_objects import AccountId


class AccountRepository(ABC):
    @abstractmethod
    async def save(self, account: Account) -> None: ...

    @abstractmethod
    async def find_by_id(self, account_id: AccountId) -> Account | None: ...

    @abstractmethod
    async def find_by_email(self, email: Email) -> Account | None: ...

    @abstractmethod
    async def exists_by_email(self, email: Email) -> bool: ...
