from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.user import User

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import (
        EmailAddress,
        EmailVerificationPolicy,
        EmailVerificationToken,
        PasswordPolicy,
    )
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort
    from pydentity.domain.ports.password_hasher import PasswordHasherPort
    from pydentity.domain.ports.verification_token_generator import (
        VerificationTokenGeneratorPort,
    )


class UserFactory:
    def __init__(
        self,
        *,
        identity_generator: IdentityGeneratorPort,
        password_hasher: PasswordHasherPort,
        verification_token_generator: VerificationTokenGeneratorPort,
        password_policy: PasswordPolicy,
        email_verification_policy: EmailVerificationPolicy,
    ) -> None:
        self._identity_generator = identity_generator
        self._password_hasher = password_hasher
        self._verification_token_generator = verification_token_generator
        self._password_policy = password_policy
        self._email_verification_policy = email_verification_policy

    async def create(
        self,
        *,
        email: EmailAddress,
        plain_password: str,
        verification_token: EmailVerificationToken | None = None,
    ) -> User:
        self._password_policy.validate(plain_password)
        password_hash = await self._password_hasher.hash(plain_password)
        user_id = self._identity_generator.new_user_id()

        return User.create(
            user_id=user_id,
            email=email,
            password_hash=password_hash,
            verification_token=verification_token,
        )
