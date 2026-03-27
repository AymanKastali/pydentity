from typing import TYPE_CHECKING

from pydentity.application.account.services import (
    GetCurrentAccountService,
    RegisterAccountService,
    VerifyEmailService,
)
from pydentity.application.auth.services import (
    AuthenticateService,
    LogoutService,
    RefreshAccessTokenService,
)
from pydentity.infrastructure.factories.account_factory import (
    DefaultAccountFactory,
)
from pydentity.infrastructure.factories.refresh_token_factory import (
    DefaultRefreshTokenFactory,
)
from pydentity.infrastructure.messaging.event_publisher import (
    InProcessEventPublisher,
)
from pydentity.infrastructure.messaging.handlers import (
    register_event_handlers,
)
from pydentity.infrastructure.persistence.account_repository import (
    SqlAlchemyAccountRepository,
)
from pydentity.infrastructure.persistence.refresh_token_repository import (
    SqlAlchemyRefreshTokenRepository,
)
from pydentity.infrastructure.persistence.unit_of_work import (
    SqlAlchemyUnitOfWork,
)
from pydentity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)
from pydentity.infrastructure.security.clock import UTCClock
from pydentity.infrastructure.security.id_generator import (
    UUIDV7IdGenerator,
)
from pydentity.infrastructure.security.jwt_access_token_service import (
    JWTAccessTokenService,
)
from pydentity.infrastructure.security.token_generator import (
    SecureTokenGenerator,
)
from pydentity.infrastructure.security.token_hasher import SHA256TokenHasher

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from pydentity.infrastructure.settings import Settings


class Container:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._clock = UTCClock()
        self._password_hasher = Argon2PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost,
            parallelism=settings.argon2_parallelism,
        )
        self._access_token_service = JWTAccessTokenService(
            private_key_path=settings.jwt_private_key_path,
            clock=self._clock,
            expire_minutes=settings.jwt_access_token_expire_minutes,
        )
        self._id_generator = UUIDV7IdGenerator()
        self._token_generator = SecureTokenGenerator()
        self._token_hasher = SHA256TokenHasher()
        self._account_factory = DefaultAccountFactory(
            id_generator=self._id_generator,
            password_hasher=self._password_hasher,
            token_generator=self._token_generator,
        )
        self._refresh_token_factory = DefaultRefreshTokenFactory(
            id_generator=self._id_generator,
            token_generator=self._token_generator,
            token_hasher=self._token_hasher,
            clock=self._clock,
            expire_days=settings.refresh_token_expire_days,
        )
        self._event_publisher = InProcessEventPublisher()
        register_event_handlers(self._event_publisher)

    @property
    def access_token_service(self) -> JWTAccessTokenService:
        return self._access_token_service

    def _create_session_dependencies(
        self, session: AsyncSession
    ) -> tuple[
        SqlAlchemyAccountRepository,
        SqlAlchemyRefreshTokenRepository,
        SqlAlchemyUnitOfWork,
    ]:
        account_repository = SqlAlchemyAccountRepository(session, self._clock)
        refresh_token_repository = SqlAlchemyRefreshTokenRepository(
            session, self._clock
        )
        unit_of_work = SqlAlchemyUnitOfWork(session)
        return account_repository, refresh_token_repository, unit_of_work

    def register_account_service(
        self, session: AsyncSession | None = None
    ) -> RegisterAccountService:
        session = session or self._get_session()
        account_repo, _, uow = self._create_session_dependencies(session)
        return RegisterAccountService(
            account_repository=account_repo,
            account_factory=self._account_factory,
            unit_of_work=uow,
            event_publisher=self._event_publisher,
        )

    def verify_email_service(
        self, session: AsyncSession | None = None
    ) -> VerifyEmailService:
        session = session or self._get_session()
        account_repo, _, uow = self._create_session_dependencies(session)
        return VerifyEmailService(
            account_repository=account_repo,
            unit_of_work=uow,
            event_publisher=self._event_publisher,
        )

    def authenticate_service(
        self, session: AsyncSession | None = None
    ) -> AuthenticateService:
        session = session or self._get_session()
        account_repo, rt_repo, uow = self._create_session_dependencies(session)
        return AuthenticateService(
            account_repository=account_repo,
            refresh_token_repository=rt_repo,
            refresh_token_factory=self._refresh_token_factory,
            password_hasher=self._password_hasher,
            access_token_service=self._access_token_service,
            unit_of_work=uow,
            event_publisher=self._event_publisher,
            access_token_expire_minutes=self._settings.jwt_access_token_expire_minutes,
        )

    def refresh_access_token_service(
        self, session: AsyncSession | None = None
    ) -> RefreshAccessTokenService:
        session = session or self._get_session()
        account_repo, rt_repo, uow = self._create_session_dependencies(session)
        return RefreshAccessTokenService(
            refresh_token_repository=rt_repo,
            account_repository=account_repo,
            refresh_token_factory=self._refresh_token_factory,
            access_token_service=self._access_token_service,
            token_hasher=self._token_hasher,
            clock=self._clock,
            unit_of_work=uow,
            event_publisher=self._event_publisher,
            access_token_expire_minutes=self._settings.jwt_access_token_expire_minutes,
        )

    def logout_service(self, session: AsyncSession | None = None) -> LogoutService:
        session = session or self._get_session()
        _, rt_repo, uow = self._create_session_dependencies(session)
        return LogoutService(
            refresh_token_repository=rt_repo,
            token_hasher=self._token_hasher,
            clock=self._clock,
            unit_of_work=uow,
            event_publisher=self._event_publisher,
        )

    def get_current_account_service(
        self, session: AsyncSession | None = None
    ) -> GetCurrentAccountService:
        session = session or self._get_session()
        account_repo, _, _ = self._create_session_dependencies(session)
        return GetCurrentAccountService(
            account_repository=account_repo,
        )

    def _get_session(self) -> AsyncSession:
        raise RuntimeError("Session not available — use request-scoped container")
