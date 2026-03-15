from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.dtos.auth import RegisterUserOutput
from pydentity.domain.exceptions.domain import EmailAlreadyTakenError
from pydentity.domain.models.value_objects import RoleName
from pydentity.domain.services.register_user import RegisterUser as RegisterUserService

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import RegisterUserInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.factories.email_address_factory import EmailAddressFactory
    from pydentity.domain.factories.user_factory import UserFactory
    from pydentity.domain.models.value_objects import EmailVerificationPolicy
    from pydentity.domain.ports.clock import ClockPort
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
        email_address_factory: EmailAddressFactory,
        verification_token_generator: VerificationTokenGeneratorPort,
        email_verification_policy: EmailVerificationPolicy,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        notification: NotificationPort,
        logger: LoggerPort,
        default_role_name: str | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._user_factory = user_factory
        self._email_address_factory = email_address_factory
        self._verification_token_generator = verification_token_generator
        self._email_verification_policy = email_verification_policy
        self._clock = clock
        self._event_publisher = event_publisher
        self._notification = notification
        self._default_role_name = default_role_name
        self._logger = logger

    async def execute(self, command: RegisterUserInput) -> RegisterUserOutput:
        self._logger.debug("registering user", email=command.email)

        email = self._email_address_factory.create(command.email)
        now = self._clock.now()

        raw_token: str | None = None
        verification_token = None

        if self._email_verification_policy.required_on_registration:
            raw_token, verification_token = self._verification_token_generator.generate(
                self._email_verification_policy.token_ttl, now
            )

        async with self._uow_factory() as uow:
            register_user_service = RegisterUserService(
                user_repo=uow.users,
                user_factory=self._user_factory,
            )
            try:
                user = await register_user_service.execute(
                    email=email,
                    plain_password=command.password,
                    verification_token=verification_token,
                )
            except EmailAlreadyTakenError:
                # Intentional: identical output prevents email
                # enumeration (client can't tell success from conflict).
                self._logger.debug(
                    "registration skipped — email already taken", email=email.address
                )
                return RegisterUserOutput(email=email.address)

            if self._default_role_name is not None:
                default_role = await uow.roles.find_by_name(
                    RoleName.create(self._default_role_name)
                )
                if default_role is not None:
                    user.assign_role(default_role.name)

            await uow.users.upsert(user)
            await uow.commit()

        self._logger.info("user registered", email=email.address)

        events = user.collect_events()

        await self._event_publisher.publish(events)

        if raw_token is not None:
            await self._notification.send_verification_email(
                email=email.address, raw_token=raw_token
            )

        return RegisterUserOutput(email=email.address)
