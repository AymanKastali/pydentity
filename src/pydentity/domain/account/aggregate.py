from typing import TYPE_CHECKING

from pydentity.domain.account.errors import (
    AccountNotActiveError,
    EmailAlreadyVerifiedError,
    InvalidVerificationTokenError,
)
from pydentity.domain.account.events import (
    AccountEmailVerified,
    AccountPasswordChanged,
    AccountRegistered,
    AccountSuspended,
)
from pydentity.domain.account.value_objects import (
    AccountStatus,
    Email,
    HashedPassword,
    VerificationToken,
)
from pydentity.domain.base import AggregateRoot

if TYPE_CHECKING:
    from pydentity.domain.account.aggregate_id import AccountId


class Account(AggregateRoot):
    def __init__(
        self,
        account_id: AccountId,
        email: Email,
        hashed_password: HashedPassword,
        status: AccountStatus,
        verification_token: VerificationToken | None,
    ) -> None:
        super().__init__(account_id.value)
        self._account_id = account_id
        self._email = email
        self._hashed_password = hashed_password
        self._status = status
        self._verification_token = verification_token

    @classmethod
    def register(
        cls,
        account_id: AccountId,
        email: Email,
        hashed_password: HashedPassword,
        verification_token: VerificationToken,
    ) -> Account:
        account = cls(
            account_id=account_id,
            email=email,
            hashed_password=hashed_password,
            status=AccountStatus.PENDING_VERIFICATION,
            verification_token=verification_token,
        )
        account._record_event(
            AccountRegistered(
                account_id=account_id.value,
                email=email.value,
            )
        )
        return account

    def verify_email(self, token: VerificationToken) -> None:
        self._ensure_pending_verification()
        self._ensure_token_matches(token)
        self._activate()
        self._record_event(AccountEmailVerified(account_id=self._account_id.value))

    def change_password(self, new_hashed_password: HashedPassword) -> None:
        self._hashed_password = new_hashed_password
        self._record_event(AccountPasswordChanged(account_id=self._account_id.value))

    def suspend(self) -> None:
        self._ensure_active()
        self._status = AccountStatus.SUSPENDED
        self._record_event(AccountSuspended(account_id=self._account_id.value))

    def _ensure_pending_verification(self) -> None:
        if self._status != AccountStatus.PENDING_VERIFICATION:
            raise EmailAlreadyVerifiedError(self._account_id.value)

    def _ensure_token_matches(self, token: VerificationToken) -> None:
        if self._verification_token is None or self._verification_token != token:
            raise InvalidVerificationTokenError(self._account_id.value)

    def _activate(self) -> None:
        self._status = AccountStatus.ACTIVE
        self._verification_token = None

    def _ensure_active(self) -> None:
        if self._status != AccountStatus.ACTIVE:
            raise AccountNotActiveError(self._account_id.value)

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def email(self) -> Email:
        return self._email

    @property
    def hashed_password(self) -> HashedPassword:
        return self._hashed_password

    @property
    def status(self) -> AccountStatus:
        return self._status

    @property
    def verification_token(self) -> VerificationToken | None:
        return self._verification_token
