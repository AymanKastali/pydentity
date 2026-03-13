from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import EmailAlreadyTakenError

if TYPE_CHECKING:
    from pydentity.domain.factories.user_factory import UserFactory
    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import (
        EmailAddress,
        EmailVerificationToken,
    )
    from pydentity.domain.ports.repositories import UserRepositoryPort


class RegisterUser:
    def __init__(
        self,
        *,
        user_repo: UserRepositoryPort,
        user_factory: UserFactory,
    ) -> None:
        self._repo = user_repo
        self._factory = user_factory

    async def execute(
        self,
        *,
        email: EmailAddress,
        plain_password: str,
        verification_token: EmailVerificationToken | None = None,
    ) -> User:
        if await self._repo.check_email_exists(email):
            raise EmailAlreadyTakenError()

        return await self._factory.create(
            email=email,
            plain_password=plain_password,
            verification_token=verification_token,
        )
