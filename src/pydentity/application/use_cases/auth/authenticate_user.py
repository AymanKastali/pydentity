from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.services import assemble_token_claims
from pydentity.domain.exceptions import InvalidCredentialsError
from pydentity.domain.models.value_objects import EmailAddress

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import (
        AuthenticateUserInput,
        AuthenticateUserOutput,
    )
    from pydentity.application.ports.token_signer import TokenSignerPort
    from pydentity.domain.factories import SessionFactory
    from pydentity.domain.models.value_objects import (
        AccountLockoutPolicy,
        TokenLifetimePolicy,
    )
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort
    from pydentity.domain.ports.password_hasher import PasswordHasherPort
    from pydentity.domain.ports.raw_token_generator import RawTokenGeneratorPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class AuthenticateUser:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        password_hasher: PasswordHasherPort,
        session_factory: SessionFactory,
        raw_token_generator: RawTokenGeneratorPort,
        token_signer: TokenSignerPort,
        identity_generator: IdentityGeneratorPort,
        clock: ClockPort,
        event_publisher: DomainEventPublisherPort,
        lockout_policy: AccountLockoutPolicy,
        token_lifetime_policy: TokenLifetimePolicy,
        token_issuer: str,
    ) -> None:
        self._uow_factory = uow_factory
        self._password_hasher = password_hasher
        self._session_factory = session_factory
        self._raw_token_generator = raw_token_generator
        self._token_signer = token_signer
        self._identity_generator = identity_generator
        self._clock = clock
        self._event_publisher = event_publisher
        self._lockout_policy = lockout_policy
        self._token_lifetime_policy = token_lifetime_policy
        self._token_issuer = token_issuer

    async def execute(self, command: AuthenticateUserInput) -> AuthenticateUserOutput:
        from pydentity.application.dtos.auth import AuthenticateUserOutput

        email = EmailAddress.from_string(command.email)
        now = self._clock.now()

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_email(email)
            if user is None:
                raise InvalidCredentialsError()

            password_valid = await user.verify_password(
                command.password, self._password_hasher, now
            )

            if not password_valid:
                user.record_failed_login(self._lockout_policy, now)
                await uow.users.save(user)
                await uow.commit()
                events = user.collect_events()
                await self._event_publisher.publish(events)
                user.clear_events()
                raise InvalidCredentialsError()

            user.record_successful_login(now)

            raw_refresh = self._raw_token_generator.generate()
            session = self._session_factory.create(
                user_id=user.id,
                raw_refresh_token=raw_refresh,
                absolute_lifetime=self._token_lifetime_policy.session_absolute_ttl,
                created_at=now,
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

            await uow.users.save(user)
            await uow.sessions.save(session)
            await uow.commit()

            events = user.collect_events() + session.collect_events()

        await self._event_publisher.publish(events)
        user.clear_events()
        session.clear_events()

        return AuthenticateUserOutput(
            access_token=access_token,
            refresh_token=raw_refresh,
            user_id=user.id.value,
            session_id=session.id.value,
        )
