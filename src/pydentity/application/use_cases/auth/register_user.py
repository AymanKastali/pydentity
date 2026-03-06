from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import EmailAlreadyTakenError
from pydentity.domain.models.value_objects import EmailAddress

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import RegisterUserInput, RegisterUserOutput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.models.value_objects import EmailVerificationPolicy
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork
    from pydentity.domain.ports.verification_token_generator import (
        VerificationTokenGeneratorPort,
    )
    from pydentity.domain.services.register_user import (
        RegisterUser as RegisterUserService,
    )


class RegisterUser:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        register_user_service: RegisterUserService,
        verification_token_generator: VerificationTokenGeneratorPort,
        email_verification_policy: EmailVerificationPolicy,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._register_user_service = register_user_service
        self._verification_token_generator = verification_token_generator
        self._email_verification_policy = email_verification_policy
        self._clock = clock
        self._event_publisher = event_publisher

    async def execute(self, command: RegisterUserInput) -> RegisterUserOutput:
        from pydentity.application.dtos.auth import RegisterUserOutput

        email = EmailAddress.from_string(command.email)
        now = self._clock.now()

        raw_token: str | None = None
        verification_token = None

        if self._email_verification_policy.required_on_registration:
            raw_token, verification_token = self._verification_token_generator.generate(
                self._email_verification_policy.token_ttl, now
            )

        async with self._uow_factory() as uow:
            try:
                user = await self._register_user_service.execute(
                    email=email,
                    plain_password=command.password,
                    verification_token=verification_token,
                    raw_token=raw_token,
                )
            except EmailAlreadyTakenError:
                return RegisterUserOutput(email=email.address)

            await uow.users.upsert(user)
            await uow.commit()

        events = user.collect_events()

        await self._event_publisher.publish(events)

        return RegisterUserOutput(email=email.address)
