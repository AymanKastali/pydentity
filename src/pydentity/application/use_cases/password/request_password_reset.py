from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.value_objects import EmailAddress

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import timedelta

    from pydentity.application.dtos.password import RequestPasswordResetInput
    from pydentity.application.ports import NotificationPort
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.reset_token_generator import ResetTokenGeneratorPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class RequestPasswordReset:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        reset_token_generator: ResetTokenGeneratorPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        notification: NotificationPort,
        reset_token_ttl: timedelta,
    ) -> None:
        self._uow_factory = uow_factory
        self._reset_token_generator = reset_token_generator
        self._clock = clock
        self._event_publisher = event_publisher
        self._notification = notification
        self._reset_token_ttl = reset_token_ttl

    async def execute(self, command: RequestPasswordResetInput) -> None:
        email = EmailAddress.from_string(command.email)
        now = self._clock.now()

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_email(email)
            if user is None:
                return

            raw_token, reset_token = self._reset_token_generator.generate(
                self._reset_token_ttl, now
            )
            user.request_password_reset(reset_token)

            await uow.users.save(user)
            await uow.commit()

            events = user.collect_events()

        await self._event_publisher.publish(events)
        user.clear_events()
        await self._notification.send_password_reset_email(
            email=email.address, raw_token=raw_token
        )
