from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import (
    EmailAlreadyRegisteredError,
    UserNotFoundError,
)
from pydentity.domain.models.value_objects import EmailAddress, UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.account import ChangeEmailInput
    from pydentity.application.ports import NotificationPort
    from pydentity.domain.models.value_objects import EmailVerificationPolicy
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork
    from pydentity.domain.ports.verification_token_generator import (
        VerificationTokenGeneratorPort,
    )


class ChangeEmail:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        verification_token_generator: VerificationTokenGeneratorPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        notification: NotificationPort,
        email_verification_policy: EmailVerificationPolicy,
    ) -> None:
        self._uow_factory = uow_factory
        self._verification_token_generator = verification_token_generator
        self._clock = clock
        self._event_publisher = event_publisher
        self._notification = notification
        self._email_verification_policy = email_verification_policy

    async def execute(self, command: ChangeEmailInput) -> None:
        new_email = EmailAddress.from_string(command.new_email)
        now = self._clock.now()

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=command.user_id))
            if user is None:
                raise UserNotFoundError(user_id=command.user_id)

            existing = await uow.users.find_by_email(new_email)
            if existing is not None:
                raise EmailAlreadyRegisteredError()

            raw_token, verification_token = self._verification_token_generator.generate(
                self._email_verification_policy.token_ttl, now
            )
            user.change_email(new_email, verification_token)

            await uow.users.save(user)
            await uow.commit()

            events = user.collect_events()

        await self._event_publisher.publish(events)
        user.clear_events()
        await self._notification.send_verification_email(
            email=new_email.address, raw_token=raw_token
        )
