from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import UserNotFoundError
from pydentity.domain.models.value_objects import EmailAddress, UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.account import ChangeEmailInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.models.value_objects import EmailVerificationPolicy
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork
    from pydentity.domain.ports.verification_token_generator import (
        VerificationTokenGeneratorPort,
    )
    from pydentity.domain.services.change_user_email import ChangeUserEmail


class ChangeEmail:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        change_user_email: ChangeUserEmail,
        verification_token_generator: VerificationTokenGeneratorPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        email_verification_policy: EmailVerificationPolicy,
    ) -> None:
        self._uow_factory = uow_factory
        self._change_user_email = change_user_email
        self._verification_token_generator = verification_token_generator
        self._clock = clock
        self._event_publisher = event_publisher
        self._email_verification_policy = email_verification_policy

    async def execute(self, command: ChangeEmailInput) -> None:
        new_email = EmailAddress.from_string(command.new_email)
        now = self._clock.now()

        raw_token, verification_token = self._verification_token_generator.generate(
            self._email_verification_policy.token_ttl, now
        )

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=command.user_id))
            if user is None:
                raise UserNotFoundError(user_id=command.user_id)

            await self._change_user_email.execute(
                user=user,
                new_email=new_email,
                verification_token=verification_token,
                raw_token=raw_token,
            )

            await uow.users.upsert(user)
            await uow.commit()

        events = user.collect_events()

        await self._event_publisher.publish(events)
