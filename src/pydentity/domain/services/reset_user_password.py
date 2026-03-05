from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions import PasswordReuseError

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import HashedResetToken, PasswordPolicy
    from pydentity.domain.ports.password_hasher import PasswordHasherPort


class ResetUserPassword:
    def __init__(
        self,
        *,
        password_hasher: PasswordHasherPort,
        password_policy: PasswordPolicy,
    ) -> None:
        self._password_hasher = password_hasher
        self._password_policy = password_policy

    async def execute(
        self,
        *,
        user: User,
        token_hash: HashedResetToken,
        new_password: str,
        now: datetime,
    ) -> None:
        self._password_policy.validate(new_password)

        for old_hash in user.password_history:
            if await self._password_hasher.verify(new_password, old_hash):
                raise PasswordReuseError(
                    history_size=self._password_policy.history_size
                )

        new_hash = await self._password_hasher.hash(new_password)
        user.reset_password(new_hash, token_hash, now)
