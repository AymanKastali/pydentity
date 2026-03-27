from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.account.aggregate import Account
    from pydentity.domain.account.value_objects import Email


class AccountFactory(ABC):
    @abstractmethod
    def register(self, email: Email, password: str) -> Account: ...
