from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.user import User

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import (
        EmailAddress,
        EmailVerificationToken,
        PasswordPolicy,
    )
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort
    from pydentity.domain.ports.password_hasher import PasswordHasherPort


class UserFactory:
    def __init__(self, *, identity_generator: IdentityGeneratorPort) -> None:
        self._identity_generator = identity_generator

    async def create(
        self,
        *,
        email: EmailAddress,
        plain_password: str,
        password_policy: PasswordPolicy,
        hasher: PasswordHasherPort,
        verification_token: EmailVerificationToken | None = None,
    ) -> User:
        user_id = self._identity_generator.new_user_id()
        return await User.create(
            user_id=user_id,
            email=email,
            plain_password=plain_password,
            password_policy=password_policy,
            hasher=hasher,
            verification_token=verification_token,
        )
