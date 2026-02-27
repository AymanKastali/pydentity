from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import EmailAlreadyRegisteredError
from pydentity.domain.models.value_objects import EmailAddress

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import RegisterUserInput, RegisterUserOutput
    from pydentity.application.ports import NotificationPort
    from pydentity.domain.factories import UserFactory
    from pydentity.domain.models.value_objects import (
        EmailVerificationPolicy,
        PasswordPolicy,
    )
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.password_hasher import PasswordHasherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork
    from pydentity.domain.ports.verification_token_generator import (
        VerificationTokenGeneratorPort,
    )


class RegisterUser:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        user_factory: UserFactory,
        password_hasher: PasswordHasherPort,
        verification_token_generator: VerificationTokenGeneratorPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        notification: NotificationPort,
        password_policy: PasswordPolicy,
        email_verification_policy: EmailVerificationPolicy,
    ) -> None:
        self._uow_factory = uow_factory
        self._user_factory = user_factory
        self._password_hasher = password_hasher
        self._verification_token_generator = verification_token_generator
        self._clock = clock
        self._event_publisher = event_publisher
        self._notification = notification
        self._password_policy = password_policy
        self._email_verification_policy = email_verification_policy

    async def execute(self, command: RegisterUserInput) -> RegisterUserOutput:
        from pydentity.application.dtos.auth import RegisterUserOutput

        email = EmailAddress.from_string(command.email)

        now = self._clock.now()

        async with self._uow_factory() as uow:
            existing = await uow.users.find_by_email(email)
            if existing is not None:
                raise EmailAlreadyRegisteredError()

            raw_token: str | None = None
            verification_token = None
            if self._email_verification_policy.required_on_registration:
                raw_token, verification_token = (
                    self._verification_token_generator.generate(
                        self._email_verification_policy.token_ttl, now
                    )
                )

            user = await self._user_factory.create(
                email=email,
                plain_password=command.password,
                password_policy=self._password_policy,
                hasher=self._password_hasher,
                verification_token=verification_token,
            )

            await uow.users.save(user)
            await uow.commit()

            events = user.collect_events()

        await self._event_publisher.publish(events)
        user.clear_events()

        if raw_token is not None:
            await self._notification.send_verification_email(
                email=email.address, raw_token=raw_token
            )

        return RegisterUserOutput(
            user_id=user.id.value,
            email=email.address,
        )
