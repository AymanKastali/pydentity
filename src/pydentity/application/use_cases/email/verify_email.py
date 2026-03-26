from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import InvalidTokenError
from pydentity.domain.exceptions import (
    VerificationTokenExpiredError,
    VerificationTokenInvalidError,
    VerificationTokenNotIssuedError,
)
from pydentity.domain.models.value_objects import HashedVerificationToken

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.email import VerifyEmailInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.timing_safe_comparator import TimingSafeComparatorPort
    from pydentity.domain.ports.token_hasher import TokenHasherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class VerifyEmail:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        token_hasher: TokenHasherPort,
        comparator: TimingSafeComparatorPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        logger: LoggerPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._token_hasher = token_hasher
        self._comparator = comparator
        self._clock = clock
        self._event_publisher = event_publisher
        self._logger = logger

    async def execute(self, command: VerifyEmailInput) -> None:
        self._logger.debug("verifying email")

        now = self._clock.now()
        token_hash = HashedVerificationToken(
            value=self._token_hasher.hash(command.token)
        )

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_verification_token_hash(token_hash)
            if user is None:
                self._logger.warning("email verification failed — invalid token")
                raise InvalidTokenError()

            try:
                token = user.email_verification_token
                if token is None:
                    raise VerificationTokenNotIssuedError()
                if token.is_expired(now):
                    raise VerificationTokenExpiredError()
                if not self._comparator.equals(
                    token.token_hash.value, token_hash.value
                ):
                    raise VerificationTokenInvalidError()
                user.verify_email()
            except (
                VerificationTokenExpiredError,
                VerificationTokenInvalidError,
                VerificationTokenNotIssuedError,
            ):
                self._logger.warning(
                    "email verification failed — token expired or invalid",
                    user_id=str(user.id.value),
                )
                raise InvalidTokenError() from None

            await uow.users.upsert(user)
            await uow.commit()

        self._logger.info("email verified", user_id=str(user.id.value))

        events = user.collect_events()
        await self._event_publisher.publish(events)
