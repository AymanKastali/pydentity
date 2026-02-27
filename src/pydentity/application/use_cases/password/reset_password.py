from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import UserNotFoundError
from pydentity.domain.models.value_objects import HashedResetToken, UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.password import ResetPasswordInput
    from pydentity.domain.models.value_objects import PasswordPolicy
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.password_hasher import PasswordHasherPort
    from pydentity.domain.ports.token_hasher import TokenHasherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class ResetPassword:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        password_hasher: PasswordHasherPort,
        token_hasher: TokenHasherPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        password_policy: PasswordPolicy,
    ) -> None:
        self._uow_factory = uow_factory
        self._password_hasher = password_hasher
        self._token_hasher = token_hasher
        self._clock = clock
        self._event_publisher = event_publisher
        self._password_policy = password_policy

    async def execute(self, command: ResetPasswordInput) -> None:
        now = self._clock.now()

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=command.user_id))
            if user is None:
                raise UserNotFoundError(user_id=command.user_id)

            token_hash = HashedResetToken(value=self._token_hasher.hash(command.token))
            await user.reset_password(
                token_hash,
                command.new_password,
                now,
                self._password_policy,
                self._password_hasher,
            )

            await uow.users.save(user)
            await uow.commit()

            events = user.collect_events()

        await self._event_publisher.publish(events)
        user.clear_events()
