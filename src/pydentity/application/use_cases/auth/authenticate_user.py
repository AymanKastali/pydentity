from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.dtos.auth import AuthenticateUserOutput
from pydentity.application.models.access_token_claims import AccessTokenClaims
from pydentity.domain.exceptions import InvalidCredentialsError
from pydentity.domain.exceptions.domain import DeviceOwnershipError, DeviceRevokedError
from pydentity.domain.models.value_objects import DeviceId, DeviceName, EmailAddress
from pydentity.domain.services.register_device import RegisterDevice

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import AuthenticateUserInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.application.ports.token_signer import TokenSignerPort
    from pydentity.domain.factories.session_factory import SessionFactory
    from pydentity.domain.models.value_objects import (
        AccountLockoutPolicy,
        TokenLifetimePolicy,
    )
    from pydentity.domain.ports.clock import ClockPort
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
        logger: LoggerPort,
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
        self._logger = logger

    async def execute(self, command: AuthenticateUserInput) -> AuthenticateUserOutput:
        email = EmailAddress.from_string(command.email)
        now = self._clock.now()

        self._logger.info("auth attempt", email=email.address)

        async with self._uow_factory() as uow:
            register_device = RegisterDevice(device_repo=uow.devices)

            # ------------------------------------------------------------------
            # 1. Authenticate user
            # ------------------------------------------------------------------
            user = await uow.users.find_by_email(email)
            if user is None:
                self._logger.warning(
                    "auth failed — invalid credentials", email=email.address
                )
                raise InvalidCredentialsError()

            stored_hash = user.ensure_can_attempt_login(now)
            password_valid = await self._password_hasher.verify(
                command.password, stored_hash
            )

            if not password_valid:
                self._logger.warning(
                    "auth failed — invalid credentials", email=email.address
                )
                user.record_failed_login(self._lockout_policy, now)
                await uow.users.upsert(user)
                await uow.commit()
                await self._event_publisher.publish(user.collect_events())
                raise InvalidCredentialsError()

            user.record_successful_login(now)

            # ------------------------------------------------------------------
            # 2. Resolve device — reuse existing, register if first time
            # ------------------------------------------------------------------
            device = await uow.devices.find_by_id(DeviceId(value=command.device_id))

            if device is None:
                device = await register_device.execute(
                    device_id=DeviceId(value=command.device_id),
                    user_id=user.id,
                    name=DeviceName(value=command.device_name),
                    raw_fingerprint=command.raw_fingerprint,
                    platform=command.platform,
                    now=now,
                )
            else:
                try:
                    device.ensure_accessible_by(user.id)
                except (DeviceOwnershipError, DeviceRevokedError) as e:
                    raise InvalidCredentialsError() from e

                device.mark_active(now)

            # ------------------------------------------------------------------
            # 3. Establish session — revokes existing, creates new
            # ------------------------------------------------------------------
            existing_session = await uow.sessions.find_active_by_device(device.id)
            if existing_session is not None:
                existing_session.revoke()

            raw_refresh = self._raw_token_generator.generate()
            session = self._session_factory.create(
                user_id=user.id,
                device_id=device.id,
                raw_refresh_token=raw_refresh,
                absolute_lifetime=self._token_lifetime_policy.session_absolute_ttl,
                created_at=now,
            )

            # ------------------------------------------------------------------
            # 4. Sign access token
            # ------------------------------------------------------------------
            roles = await uow.roles.find_by_names(user.role_names)
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
            # 5. Persist everything atomically
            # ------------------------------------------------------------------
            await uow.users.upsert(user)
            await uow.devices.upsert(device)
            await uow.sessions.upsert(session)
            if existing_session is not None:
                await uow.sessions.upsert(existing_session)
            await uow.commit()

        events = (
            user.collect_events()
            + device.collect_events()
            + session.collect_events()
            + (
                existing_session.collect_events()
                if existing_session is not None
                else []
            )
        )
        await self._event_publisher.publish(events)

        self._logger.info(
            "auth success",
            user_id=user.id.value,
            session_id=session.id.value,
            device_id=device.id.value,
        )

        return AuthenticateUserOutput(
            access_token=access_token,
            refresh_token=raw_refresh,
            user_id=user.id.value,
            session_id=session.id.value,
            device_id=device.id.value,
        )
