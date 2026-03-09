from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import InvalidTokenError
from pydentity.domain.models.value_objects import HashedVerificationToken

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.email import VerifyEmailInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.token_hasher import TokenHasherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class VerifyEmail:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        token_hasher: TokenHasherPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._token_hasher = token_hasher
        self._clock = clock
        self._event_publisher = event_publisher

    async def execute(self, command: VerifyEmailInput) -> None:
        now = self._clock.now()
        token_hash = HashedVerificationToken(
            value=self._token_hasher.hash(command.token)
        )

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_verification_token_hash(token_hash)
            if user is None:
                raise InvalidTokenError()

            user.verify_email(token_hash, now)

            await uow.users.upsert(user)
            await uow.commit()

        events = user.collect_events()

        await self._event_publisher.publish(events)
