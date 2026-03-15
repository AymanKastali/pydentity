from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import timedelta

    from pydentity.application.dtos.password import RequestPasswordResetInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.factories.email_address_factory import EmailAddressFactory
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.reset_token_generator import ResetTokenGeneratorPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class RequestPasswordReset:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        email_address_factory: EmailAddressFactory,
        reset_token_generator: ResetTokenGeneratorPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        notification: NotificationPort,
        reset_token_ttl: timedelta,
        logger: LoggerPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._email_address_factory = email_address_factory
        self._reset_token_generator = reset_token_generator
        self._clock = clock
        self._event_publisher = event_publisher
        self._notification = notification
        self._reset_token_ttl = reset_token_ttl
        self._logger = logger

    async def execute(self, command: RequestPasswordResetInput) -> None:
        self._logger.debug("requesting password reset", email=command.email)

        email = self._email_address_factory.create(command.email)
        now = self._clock.now()

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_email(email)
            if user is None:
                self._logger.debug("password reset requested for unknown email")
                return

            raw_token, reset_token = self._reset_token_generator.generate(
                self._reset_token_ttl, now
            )

            user.request_password_reset(reset_token)

            await uow.users.upsert(user)
            await uow.commit()

        self._logger.info("password reset requested", user_id=user.id.value)

        events = user.collect_events()
        await self._event_publisher.publish(events)

        await self._notification.send_password_reset_email(
            email=user.email.address, raw_token=raw_token
        )
