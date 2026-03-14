from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions import InvalidCredentialsError, PasswordReuseError

if TYPE_CHECKING:
    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import HashedPassword, PasswordPolicy
    from pydentity.domain.ports.password_hasher import PasswordHasherPort


class ChangeUserPassword:
    def __init__(
        self,
        *,
        password_hasher: PasswordHasherPort,
        password_policy: PasswordPolicy,
    ) -> None:
        self._password_hasher = password_hasher
        self._password_policy = password_policy

    async def _ensure_current_password_valid(
        self, current_password: str, stored_hash: HashedPassword
    ) -> None:
        if not await self._password_hasher.verify(current_password, stored_hash):
            raise InvalidCredentialsError()

    async def _ensure_password_not_reused(
        self, new_password: str, history: tuple[HashedPassword, ...]
    ) -> None:
        for old_hash in history:
            if await self._password_hasher.verify(new_password, old_hash):
                raise PasswordReuseError(
                    history_size=self._password_policy.history_size
                )

    async def execute(
        self,
        *,
        user: User,
        current_password: str,
        new_password: str,
    ) -> None:
        await self._ensure_current_password_valid(current_password, user.password_hash)
        self._password_policy.validate(new_password)
        await self._ensure_password_not_reused(new_password, user.password_history)

        new_hash = await self._password_hasher.hash(new_password)
        user.change_password(new_hash, history_size=self._password_policy.history_size)
