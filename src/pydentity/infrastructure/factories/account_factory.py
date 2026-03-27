from typing import TYPE_CHECKING

from pydentity.domain.account.aggregate import Account
from pydentity.domain.account.aggregate_id import AccountId
from pydentity.domain.account.factory import AccountFactory
from pydentity.domain.account.value_objects import HashedPassword, VerificationToken

if TYPE_CHECKING:
    from pydentity.application.services.id_generator import IdGenerator
    from pydentity.application.services.password_hasher import PasswordHasher
    from pydentity.application.services.token_generator import TokenGenerator
    from pydentity.domain.account.value_objects import Email


class DefaultAccountFactory(AccountFactory):
    def __init__(
        self,
        id_generator: IdGenerator,
        password_hasher: PasswordHasher,
        token_generator: TokenGenerator,
    ) -> None:
        self._id_generator = id_generator
        self._password_hasher = password_hasher
        self._token_generator = token_generator

    def register(self, email: Email, password: str) -> Account:
        return Account.register(
            account_id=AccountId(self._id_generator.generate()),
            email=email,
            hashed_password=HashedPassword(self._password_hasher.hash(password)),
            verification_token=VerificationToken(self._token_generator.generate()),
        )
