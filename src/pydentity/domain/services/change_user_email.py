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
        raw_token: str | None = None,
    ) -> None:
        existing = await self._repo.find_by_email(new_email)
        if existing is not None:
            raise EmailAlreadyTakenError()

        user.change_email(new_email, verification_token)

        if verification_token is not None and raw_token is not None:
            user.record_verification_token_issued(
                raw_token=raw_token, email=new_email.address
            )
