from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.dtos.auth import RefreshAccessTokenOutput
from pydentity.application.exceptions import InvalidTokenError
from pydentity.application.models.access_token_claims import AccessTokenClaims
from pydentity.domain.exceptions import AccountNotActiveError
from pydentity.domain.models.value_objects import SessionId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import RefreshAccessTokenInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.application.ports.token_signer import TokenSignerPort
    from pydentity.domain.models.value_objects import TokenLifetimePolicy
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort
    from pydentity.domain.ports.raw_token_generator import RawTokenGeneratorPort
    from pydentity.domain.ports.token_hasher import TokenHasherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class RefreshAccessToken:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        token_hasher: TokenHasherPort,
        raw_token_generator: RawTokenGeneratorPort,
        token_signer: TokenSignerPort,
        identity_generator: IdentityGeneratorPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        token_lifetime_policy: TokenLifetimePolicy,
        token_issuer: str,
        logger: LoggerPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._token_hasher = token_hasher
        self._raw_token_generator = raw_token_generator
        self._token_signer = token_signer
        self._identity_generator = identity_generator
        self._clock = clock
        self._event_publisher = event_publisher
        self._token_lifetime_policy = token_lifetime_policy
        self._token_issuer = token_issuer
        self._logger = logger

    async def execute(
        self, command: RefreshAccessTokenInput
    ) -> RefreshAccessTokenOutput:
        now = self._clock.now()

        async with self._uow_factory() as uow:
            # ------------------------------------------------------------------
            # 1. Load session
            # ------------------------------------------------------------------
            session = await uow.sessions.find_by_id(SessionId(value=command.session_id))
            if session is None:
                raise InvalidTokenError()

            # ------------------------------------------------------------------
            # 2. Validate user is still active
            # ------------------------------------------------------------------
            user = await uow.users.find_by_id(session.user_id)
            if user is None:
                if session.is_active:
                    session.revoke()
                await uow.sessions.upsert(session)
                await uow.commit()
                events = session.collect_events()
                await self._event_publisher.publish(events)
                raise AccountNotActiveError(status=None)
            if not user.is_active:
                if session.is_active:
                    session.revoke()
                await uow.sessions.upsert(session)
                await uow.commit()
                events = session.collect_events()
                await self._event_publisher.publish(events)
                raise AccountNotActiveError(status=user.status)

            # ------------------------------------------------------------------
            # 3. Validate device is still active
            # ------------------------------------------------------------------
            device = await uow.devices.get_by_id(session.device_id)
            if device is None or not device.is_active:
                if session.is_active:
                    session.revoke()
                await uow.sessions.upsert(session)
                await uow.commit()
                events = session.collect_events()
                await self._event_publisher.publish(events)
                raise InvalidTokenError()

            # ------------------------------------------------------------------
            # 4. Rotate refresh token
            # ------------------------------------------------------------------
            new_raw_refresh = self._raw_token_generator.generate()
            session.rotate_refresh_token(
                command.refresh_token,
                new_raw_refresh,
                self._token_hasher,
                now,
                email=user.email.address,
            )

            # ------------------------------------------------------------------
            # 5. Bump device last_active
            # ------------------------------------------------------------------
            device.mark_active(now)

            # ------------------------------------------------------------------
            # 6. Sign new access token
            # ------------------------------------------------------------------
            roles = await uow.roles.find_by_ids(user.role_ids)
            claims = AccessTokenClaims.create(
                issuer=self._token_issuer,
                subject=user.id,
                session_id=session.id,
                issued_at=now,
                token_lifetime_policy=self._token_lifetime_policy,
                token_id=self._identity_generator.new_token_id(),
                roles=roles,
            )
            access_token = await self._token_signer.sign(claims)

            # ------------------------------------------------------------------
            # 7. Persist everything atomically
            # ------------------------------------------------------------------
            await uow.sessions.upsert(session)
            await uow.devices.upsert(device)
            await uow.commit()

        events = session.collect_events() + device.collect_events()
        await self._event_publisher.publish(events)

        self._logger.debug("token refreshed", session_id=command.session_id)

        return RefreshAccessTokenOutput(
            access_token=access_token,
            refresh_token=new_raw_refresh,
        )
