from typing import TYPE_CHECKING

from pydentity.authentication.domain.account.errors import (
    EmailAlreadyTakenError,
    PasswordReuseError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.authentication.domain.account.repository import AccountRepository
    from pydentity.authentication.domain.account.value_objects import (
        EmailAddress,
        HashedPassword,
        HashedPasswordHistory,
    )


class PreventPasswordReuse:
    @classmethod
    def check(
        cls,
        raw_password: str,
        current_password: HashedPassword,
        password_history: HashedPasswordHistory,
        password_hash_verifier: Callable[[str, HashedPassword], bool],
    ) -> None:
        cls._guard_not_current_password(
            raw_password, current_password, password_hash_verifier
        )
        cls._guard_not_in_history(
            raw_password, password_history, password_hash_verifier
        )

    @classmethod
    def _guard_not_current_password(
        cls,
        raw_password: str,
        current_password: HashedPassword,
        password_hash_verifier: Callable[[str, HashedPassword], bool],
    ) -> None:
        if password_hash_verifier(raw_password, current_password):
            raise PasswordReuseError()

    @classmethod
    def _guard_not_in_history(
        cls,
        raw_password: str,
        password_history: HashedPasswordHistory,
        password_hash_verifier: Callable[[str, HashedPassword], bool],
    ) -> None:
        for hashed_password in password_history.hashes:
            if password_hash_verifier(raw_password, hashed_password):
                raise PasswordReuseError()


class PreventDuplicateEmail:
    @classmethod
    async def check(
        cls, email: EmailAddress, account_repository: AccountRepository
    ) -> None:
        existing_account = await account_repository.find_by_email(email)
        if existing_account is not None:
            raise EmailAlreadyTakenError()
