"""Manual DI container — wires adapters into use cases.

Build once at startup via ``Container.build()``, store in ``app.state.container``,
and inject through ``get_container`` in FastAPI ``Depends`` chains.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request
from redis.asyncio import Redis

from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.config.permissions import PermissionRegistry
from pydentity.adapters.outbound.composite_audit_trail import CompositeAuditTrail
from pydentity.adapters.outbound.events.redis_event_publisher import (
    RedisEventPublisher,
)
from pydentity.adapters.outbound.events.redis_event_subscriber import (
    RedisEventSubscriber,
)
from pydentity.adapters.outbound.log_audit_trail import LogAuditTrail
from pydentity.adapters.outbound.logging.setup import setup_logging
from pydentity.adapters.outbound.persistence.postgres.audit_trail import (
    PostgresAuditTrail,
)
from pydentity.adapters.outbound.persistence.postgres.container import (
    get_session_factory,
    get_uow,
)
from pydentity.adapters.outbound.security.clock import UtcClock
from pydentity.adapters.outbound.security.identity_generator import (
    UlidIdentityGenerator,
)
from pydentity.adapters.outbound.security.jwt_token_signer import HmacSha256JwtSigner
from pydentity.adapters.outbound.security.jwt_token_verifier import (
    HmacSha256JwtVerifier,
)
from pydentity.adapters.outbound.security.password_hasher import ScryptPasswordHasher
from pydentity.adapters.outbound.security.token_generators import (
    HashedResetTokenGenerator,
    HashedVerificationTokenGenerator,
    SecretsRawTokenGenerator,
)
from pydentity.adapters.outbound.security.token_hasher import Sha256TokenHasher
from pydentity.adapters.outbound.smtp_notification import SmtpNotification
from pydentity.application.use_cases.account.change_email import ChangeEmail
from pydentity.application.use_cases.account.deactivate_user import DeactivateUser
from pydentity.application.use_cases.account.reactivate_user import ReactivateUser
from pydentity.application.use_cases.account.suspend_user import SuspendUser
from pydentity.application.use_cases.auth.authenticate_user import AuthenticateUser
from pydentity.application.use_cases.auth.logout_user import LogoutUser
from pydentity.application.use_cases.auth.refresh_access_token import RefreshAccessToken
from pydentity.application.use_cases.auth.register_user import RegisterUser
from pydentity.application.use_cases.email.reissue_verification_token import (
    ReissueVerificationToken,
)
from pydentity.application.use_cases.email.verify_email import VerifyEmail
from pydentity.application.use_cases.password.change_password import ChangePassword
from pydentity.application.use_cases.password.request_password_reset import (
    RequestPasswordReset,
)
from pydentity.application.use_cases.password.reset_password import ResetPassword
from pydentity.application.use_cases.role.add_permission_to_role import (
    AddPermissionToRole,
)
from pydentity.application.use_cases.role.assign_role_to_user import AssignRoleToUser
from pydentity.application.use_cases.role.change_role_description import (
    ChangeRoleDescription,
)
from pydentity.application.use_cases.role.create_role import CreateRole
from pydentity.application.use_cases.role.remove_permission_from_role import (
    RemovePermissionFromRole,
)
from pydentity.application.use_cases.role.revoke_role_from_user import (
    RevokeRoleFromUser,
)
from pydentity.domain.factories.session_factory import SessionFactory
from pydentity.domain.factories.user_factory import UserFactory
from pydentity.domain.services.change_user_password import ChangeUserPassword
from pydentity.domain.services.reset_user_password import ResetUserPassword

if TYPE_CHECKING:
    from datetime import timedelta

    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.application.ports.token_signer import TokenSignerPort
    from pydentity.application.ports.token_verifier import TokenVerifierPort
    from pydentity.domain.models.value_objects import (
        AccountLockoutPolicy,
        DevicePolicy,
        EmailVerificationPolicy,
        PasswordPolicy,
        TokenLifetimePolicy,
    )
    from pydentity.domain.ports.clock import ClockPort
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort
    from pydentity.domain.ports.password_hasher import PasswordHasherPort
    from pydentity.domain.ports.raw_token_generator import RawTokenGeneratorPort
    from pydentity.domain.ports.reset_token_generator import ResetTokenGeneratorPort
    from pydentity.domain.ports.token_hasher import TokenHasherPort
    from pydentity.domain.ports.verification_token_generator import (
        VerificationTokenGeneratorPort,
    )


@dataclass
class Container:
    logger: LoggerPort
    password_hasher: PasswordHasherPort
    token_hasher: TokenHasherPort
    token_signer: TokenSignerPort
    token_verifier: TokenVerifierPort
    identity_generator: IdentityGeneratorPort
    clock: ClockPort
    raw_token_generator: RawTokenGeneratorPort
    verification_token_generator: VerificationTokenGeneratorPort
    reset_token_generator: ResetTokenGeneratorPort
    event_publisher: DomainEventPublisherPort
    event_subscriber: RedisEventSubscriber
    redis: Redis
    notification: NotificationPort
    password_policy: PasswordPolicy
    email_verification_policy: EmailVerificationPolicy
    lockout_policy: AccountLockoutPolicy
    token_lifetime_policy: TokenLifetimePolicy
    device_policy: DevicePolicy
    token_issuer: str
    reset_token_ttl: timedelta

    @classmethod
    def build(cls) -> Container:
        settings = get_app_settings()
        sec = settings.security
        redis_settings = settings.redis

        redis_client = Redis.from_url(redis_settings.url, decode_responses=True)

        notification = SmtpNotification(settings.smtp)
        log_audit_trail = LogAuditTrail()
        postgres_audit_trail = PostgresAuditTrail(
            session_factory=get_session_factory(),
        )
        audit_trail = CompositeAuditTrail(
            delegates=[log_audit_trail, postgres_audit_trail],
        )

        event_publisher = RedisEventPublisher(
            redis=redis_client,
            channel=redis_settings.event_channel,
        )
        event_subscriber = RedisEventSubscriber(
            redis=redis_client,
            channel=redis_settings.event_channel,
            notification=notification,
            audit_trail=audit_trail,
        )

        return cls(
            logger=setup_logging(),
            password_hasher=ScryptPasswordHasher(),
            token_hasher=Sha256TokenHasher(),
            token_signer=HmacSha256JwtSigner(secret=sec.jwt_secret),
            token_verifier=HmacSha256JwtVerifier(secret=sec.jwt_secret),
            identity_generator=UlidIdentityGenerator(),
            clock=UtcClock(),
            raw_token_generator=SecretsRawTokenGenerator(),
            verification_token_generator=HashedVerificationTokenGenerator(),
            reset_token_generator=HashedResetTokenGenerator(),
            event_publisher=event_publisher,
            event_subscriber=event_subscriber,
            redis=redis_client,
            notification=notification,
            password_policy=sec.password_policy,
            email_verification_policy=sec.email_verification_policy,
            lockout_policy=sec.lockout_policy,
            token_lifetime_policy=sec.token_lifetime_policy,
            device_policy=sec.device_policy,
            token_issuer=sec.token_issuer,
            reset_token_ttl=sec.reset_token_ttl,
        )


def get_container(request: Request) -> Container:
    return request.app.state.container  # type: ignore[no-any-return]


# ── Auth use cases ─────────────────────────────────────────────────────


def get_register_user(
    c: Annotated[Container, Depends(get_container)],
) -> RegisterUser:
    user_factory = UserFactory(
        identity_generator=c.identity_generator,
        password_hasher=c.password_hasher,
        verification_token_generator=c.verification_token_generator,
        password_policy=c.password_policy,
        email_verification_policy=c.email_verification_policy,
    )
    return RegisterUser(
        uow_factory=get_uow,
        user_factory=user_factory,
        verification_token_generator=c.verification_token_generator,
        email_verification_policy=c.email_verification_policy,
        clock=c.clock,
        event_publisher=c.event_publisher,
        notification=c.notification,
        default_role_name=PermissionRegistry.DEFAULT_ROLE_NAME,
        logger=c.logger,
    )


def get_authenticate_user(
    c: Annotated[Container, Depends(get_container)],
) -> AuthenticateUser:
    session_factory = SessionFactory(
        token_hasher=c.token_hasher,
        identity_generator=c.identity_generator,
    )
    return AuthenticateUser(
        uow_factory=get_uow,
        password_hasher=c.password_hasher,
        session_factory=session_factory,
        raw_token_generator=c.raw_token_generator,
        token_signer=c.token_signer,
        identity_generator=c.identity_generator,
        clock=c.clock,
        event_publisher=c.event_publisher,
        lockout_policy=c.lockout_policy,
        token_lifetime_policy=c.token_lifetime_policy,
        device_policy=c.device_policy,
        token_issuer=c.token_issuer,
        logger=c.logger,
    )


def get_refresh_access_token(
    c: Annotated[Container, Depends(get_container)],
) -> RefreshAccessToken:
    return RefreshAccessToken(
        uow_factory=get_uow,
        token_hasher=c.token_hasher,
        raw_token_generator=c.raw_token_generator,
        token_signer=c.token_signer,
        identity_generator=c.identity_generator,
        clock=c.clock,
        event_publisher=c.event_publisher,
        token_lifetime_policy=c.token_lifetime_policy,
        token_issuer=c.token_issuer,
        logger=c.logger,
    )


def get_logout_user(
    c: Annotated[Container, Depends(get_container)],
) -> LogoutUser:
    return LogoutUser(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


# ── Account use cases ─────────────────────────────────────────────────


def get_change_email(
    c: Annotated[Container, Depends(get_container)],
) -> ChangeEmail:
    return ChangeEmail(
        uow_factory=get_uow,
        verification_token_generator=c.verification_token_generator,
        clock=c.clock,
        event_publisher=c.event_publisher,
        notification=c.notification,
        email_verification_policy=c.email_verification_policy,
        logger=c.logger,
    )


def get_suspend_user(
    c: Annotated[Container, Depends(get_container)],
) -> SuspendUser:
    return SuspendUser(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_reactivate_user(
    c: Annotated[Container, Depends(get_container)],
) -> ReactivateUser:
    return ReactivateUser(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_deactivate_user(
    c: Annotated[Container, Depends(get_container)],
) -> DeactivateUser:
    return DeactivateUser(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


# ── Email use cases ───────────────────────────────────────────────────


def get_verify_email(
    c: Annotated[Container, Depends(get_container)],
) -> VerifyEmail:
    return VerifyEmail(
        uow_factory=get_uow,
        token_hasher=c.token_hasher,
        clock=c.clock,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_reissue_verification_token(
    c: Annotated[Container, Depends(get_container)],
) -> ReissueVerificationToken:
    return ReissueVerificationToken(
        uow_factory=get_uow,
        verification_token_generator=c.verification_token_generator,
        clock=c.clock,
        event_publisher=c.event_publisher,
        notification=c.notification,
        email_verification_policy=c.email_verification_policy,
        logger=c.logger,
    )


# ── Password use cases ────────────────────────────────────────────────


def get_request_password_reset(
    c: Annotated[Container, Depends(get_container)],
) -> RequestPasswordReset:
    return RequestPasswordReset(
        uow_factory=get_uow,
        reset_token_generator=c.reset_token_generator,
        clock=c.clock,
        event_publisher=c.event_publisher,
        notification=c.notification,
        reset_token_ttl=c.reset_token_ttl,
        logger=c.logger,
    )


def get_reset_password(
    c: Annotated[Container, Depends(get_container)],
) -> ResetPassword:
    reset_user_password = ResetUserPassword(
        password_hasher=c.password_hasher,
        password_policy=c.password_policy,
    )
    return ResetPassword(
        uow_factory=get_uow,
        reset_user_password=reset_user_password,
        token_hasher=c.token_hasher,
        clock=c.clock,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_change_password(
    c: Annotated[Container, Depends(get_container)],
) -> ChangePassword:
    change_user_password = ChangeUserPassword(
        password_hasher=c.password_hasher,
        password_policy=c.password_policy,
    )
    return ChangePassword(
        uow_factory=get_uow,
        change_user_password=change_user_password,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


# ── Role use cases ────────────────────────────────────────────────────


def get_create_role(
    c: Annotated[Container, Depends(get_container)],
) -> CreateRole:
    return CreateRole(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_change_role_description(
    c: Annotated[Container, Depends(get_container)],
) -> ChangeRoleDescription:
    return ChangeRoleDescription(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_add_permission_to_role(
    c: Annotated[Container, Depends(get_container)],
) -> AddPermissionToRole:
    return AddPermissionToRole(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_remove_permission_from_role(
    c: Annotated[Container, Depends(get_container)],
) -> RemovePermissionFromRole:
    return RemovePermissionFromRole(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_assign_role_to_user(
    c: Annotated[Container, Depends(get_container)],
) -> AssignRoleToUser:
    return AssignRoleToUser(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )


def get_revoke_role_from_user(
    c: Annotated[Container, Depends(get_container)],
) -> RevokeRoleFromUser:
    return RevokeRoleFromUser(
        uow_factory=get_uow,
        event_publisher=c.event_publisher,
        logger=c.logger,
    )
