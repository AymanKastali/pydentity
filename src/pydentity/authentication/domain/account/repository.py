from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.authentication.domain.account.aggregate import Account
    from pydentity.authentication.domain.account.value_objects import EmailAddress
    from pydentity.shared_kernel import AccountId, IdentityId


class AccountRepository(ABC):
    @abstractmethod
    async def save(self, account: Account) -> None: ...

    @abstractmethod
    async def find_by_id(self, account_id: AccountId) -> Account | None: ...

    @abstractmethod
    async def find_by_email(self, email: EmailAddress) -> Account | None: ...

    @abstractmethod
    async def find_by_identity_id(self, identity_id: IdentityId) -> Account | None: ...
