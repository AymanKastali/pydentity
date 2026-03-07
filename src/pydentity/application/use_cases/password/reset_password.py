from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import UserNotFoundError
from pydentity.domain.models.value_objects import HashedResetToken, UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.password import ResetPasswordInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.token_hasher import TokenHasherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork
    from pydentity.domain.services.reset_user_password import ResetUserPassword


class ResetPassword:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        reset_user_password: ResetUserPassword,
        token_hasher: TokenHasherPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._reset_user_password = reset_user_password
        self._token_hasher = token_hasher
        self._clock = clock
        self._event_publisher = event_publisher

    async def execute(self, command: ResetPasswordInput) -> None:
        now = self._clock.now()

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=command.user_id))
            if user is None:
                raise UserNotFoundError(user_id=command.user_id)

            token_hash = HashedResetToken(value=self._token_hasher.hash(command.token))

            await self._reset_user_password.execute(
                user=user,
                token_hash=token_hash,
                new_password=command.new_password,
                now=now,
            )

            await uow.users.upsert(user)
            await uow.commit()

        events = user.collect_events()

        await self._event_publisher.publish(events)
