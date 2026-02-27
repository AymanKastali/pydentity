from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import SessionNotFoundError
from pydentity.application.services import assemble_token_claims
from pydentity.domain.exceptions import AccountNotActiveError
from pydentity.domain.models.value_objects import SessionId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import (
        RefreshAccessTokenInput,
        RefreshAccessTokenOutput,
    )
    from pydentity.application.ports.token_signer import TokenSignerPort
    from pydentity.domain.models.value_objects import TokenLifetimePolicy
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
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

    async def execute(
        self, command: RefreshAccessTokenInput
    ) -> RefreshAccessTokenOutput:
        from pydentity.application.dtos.auth import RefreshAccessTokenOutput

        now = self._clock.now()

        async with self._uow_factory() as uow:
            session = await uow.sessions.find_by_id(SessionId(value=command.session_id))
            if session is None:
                raise SessionNotFoundError(session_id=command.session_id)

            new_raw_refresh = self._raw_token_generator.generate()
            session.rotate_refresh_token(
                command.refresh_token, new_raw_refresh, self._token_hasher, now
            )

            user = await uow.users.find_by_id(session.user_id)
            if user is None or not user.is_active:
                session.revoke()
                await uow.sessions.save(session)
                await uow.commit()
                events = session.collect_events()
                await self._event_publisher.publish(events)
                session.clear_events()
                raise AccountNotActiveError(
                    status=user.status if user is not None else None
                )

            roles = await uow.roles.find_by_ids(user.role_ids)
            claims = assemble_token_claims(
                issuer=self._token_issuer,
                subject=user.id,
                session_id=session.id,
                issued_at=now,
                token_lifetime_policy=self._token_lifetime_policy,
                token_id=self._identity_generator.new_token_id(),
                roles=roles,
            )
            access_token = await self._token_signer.sign(claims)

            await uow.sessions.save(session)
            await uow.commit()

            events = session.collect_events()

        await self._event_publisher.publish(events)
        session.clear_events()

        return RefreshAccessTokenOutput(
            access_token=access_token,
            refresh_token=new_raw_refresh,
        )
