from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import EmailAlreadyTakenError

if TYPE_CHECKING:
    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import (
        EmailAddress,
        EmailVerificationToken,
    )
    from pydentity.domain.ports.repositories import UserRepositoryPort


class ChangeUserEmail:
    def __init__(self, *, user_repo: UserRepositoryPort) -> None:
        self._repo = user_repo

    async def execute(
        self,
        *,
        user: User,
        new_email: EmailAddress,
        verification_token: EmailVerificationToken | None = None,
    ) -> None:
        if await self._repo.check_email_exists(new_email):
            raise EmailAlreadyTakenError()

        user.change_email(new_email, verification_token)
