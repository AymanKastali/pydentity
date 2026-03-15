from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import InvalidTokenError
from pydentity.domain.exceptions import (
    ResetTokenExpiredError,
    ResetTokenInvalidError,
    ResetTokenNotIssuedError,
)
from pydentity.domain.models.value_objects import HashedResetToken

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.password import ResetPasswordInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
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
        logger: LoggerPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._reset_user_password = reset_user_password
        self._token_hasher = token_hasher
        self._clock = clock
        self._event_publisher = event_publisher
        self._logger = logger

    async def execute(self, command: ResetPasswordInput) -> None:
        token_hash = HashedResetToken(value=self._token_hasher.hash(command.token))
        now = self._clock.now()

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_reset_token_hash(token_hash)
            if user is None:
                self._logger.warning("password reset failed — invalid token")
                raise InvalidTokenError()

            self._logger.debug("resetting password", user_id=user.id.value)

            try:
                await self._reset_user_password.execute(
                    user=user,
                    token_hash=token_hash,
                    new_password=command.new_password,
                    now=now,
                )
            except (
                ResetTokenExpiredError,
                ResetTokenInvalidError,
                ResetTokenNotIssuedError,
            ):
                self._logger.warning(
                    "password reset failed — invalid token", user_id=user.id.value
                )
                raise InvalidTokenError() from None

            await uow.users.upsert(user)

            active_sessions = await uow.sessions.find_active_by_user_id(user.id)
            for session in active_sessions:
                session.revoke()
                await uow.sessions.upsert(session)

            await uow.commit()

        self._logger.info("password reset", user_id=user.id.value)

        events = user.collect_events()
        for session in active_sessions:
            events.extend(session.collect_events())
        await self._event_publisher.publish(events)
