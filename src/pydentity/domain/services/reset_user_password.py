from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions import (
    PasswordReuseError,
    ResetTokenExpiredError,
    ResetTokenInvalidError,
    ResetTokenNotIssuedError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import HashedResetToken, PasswordPolicy
    from pydentity.domain.ports.password_hasher import PasswordHasherPort
    from pydentity.domain.ports.timing_safe_comparator import TimingSafeComparatorPort


class ResetUserPassword:
    def __init__(
        self,
        *,
        password_hasher: PasswordHasherPort,
        password_policy: PasswordPolicy,
        comparator: TimingSafeComparatorPort,
    ) -> None:
        self._password_hasher = password_hasher
        self._password_policy = password_policy
        self._comparator = comparator

    async def execute(
        self,
        *,
        user: User,
        token_hash: HashedResetToken,
        new_password: str,
        now: datetime,
    ) -> None:
        self._password_policy.validate(new_password)

        reset_token = user.password_reset_token
        if reset_token is None:
            raise ResetTokenNotIssuedError()
        if reset_token.is_expired(now):
            raise ResetTokenExpiredError()
        if not self._comparator.equals(reset_token.token_hash.value, token_hash.value):
            raise ResetTokenInvalidError()

        for old_hash in user.password_history:
            if await self._password_hasher.verify(new_password, old_hash):
                raise PasswordReuseError(
                    history_size=self._password_policy.history_size
                )

        new_hash = await self._password_hasher.hash(new_password)
        user.reset_password(new_hash, history_size=self._password_policy.history_size)
