from typing import TYPE_CHECKING

from pydentity.application.auth.dtos import (
    AuthenticateDTO,
    LogoutDTO,
    RefreshDTO,
    TokenPairDTO,
)
from pydentity.domain.account.errors import (
    AccountNotActiveError,
    AccountNotFoundError,
    InvalidCredentialsError,
)
from pydentity.domain.account.value_objects import AccountStatus, Email
from pydentity.domain.refresh_token.errors import (
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    RefreshTokenRevokedError,
)
from pydentity.domain.refresh_token.events import RefreshTokenFamilyRevoked

if TYPE_CHECKING:
    from pydentity.application.services.access_token_service import (
        AccessTokenService,
    )
    from pydentity.application.services.clock import Clock
    from pydentity.application.services.event_publisher import EventPublisher
    from pydentity.application.services.password_hasher import PasswordHasher
    from pydentity.application.services.token_hasher import TokenHasher
    from pydentity.application.services.unit_of_work import UnitOfWork
    from pydentity.domain.account.aggregate import Account
    from pydentity.domain.account.repository import AccountRepository
    from pydentity.domain.refresh_token.aggregate import RefreshToken
    from pydentity.domain.refresh_token.factory import RefreshTokenFactory
    from pydentity.domain.refresh_token.repository import RefreshTokenRepository

ACCESS_TOKEN_EXPIRE_MINUTES = 15


class AuthenticateService:
    def __init__(
        self,
        account_repository: AccountRepository,
        refresh_token_repository: RefreshTokenRepository,
        refresh_token_factory: RefreshTokenFactory,
        password_hasher: PasswordHasher,
        access_token_service: AccessTokenService,
        unit_of_work: UnitOfWork,
        event_publisher: EventPublisher,
        access_token_expire_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES,
    ) -> None:
        self._account_repository = account_repository
        self._refresh_token_repository = refresh_token_repository
        self._refresh_token_factory = refresh_token_factory
        self._password_hasher = password_hasher
        self._access_token_service = access_token_service
        self._unit_of_work = unit_of_work
        self._event_publisher = event_publisher
        self._access_token_expire_minutes = access_token_expire_minutes

    async def execute(self, dto: AuthenticateDTO) -> TokenPairDTO:
        account = await self._verify_credentials(dto.email, dto.password)
        self._ensure_account_is_active(account)
        raw_token, refresh_token = self._issue_refresh_token(account)
        access_token = self._create_access_token(account)
        await self._persist(refresh_token)
        self._event_publisher.publish(refresh_token.collect_events())
        return self._to_token_pair(access_token, raw_token)

    async def _verify_credentials(self, email: str, password: str) -> Account:
        account = await self._account_repository.find_by_email(Email(email))
        if account is None:
            raise InvalidCredentialsError()
        if not self._password_hasher.verify(password, account.hashed_password.value):
            raise InvalidCredentialsError()
        return account

    @classmethod
    def _ensure_account_is_active(cls, account: Account) -> None:
        if account.status != AccountStatus.ACTIVE:
            raise AccountNotActiveError(account.account_id.value)

    def _issue_refresh_token(self, account: Account) -> tuple[str, RefreshToken]:
        return self._refresh_token_factory.issue(account.account_id)

    def _create_access_token(self, account: Account) -> str:
        return self._access_token_service.create_access_token(
            account_id=str(account.account_id.value),
            email=account.email.value,
        )

    async def _persist(self, refresh_token: RefreshToken) -> None:
        async with self._unit_of_work:
            await self._refresh_token_repository.save(refresh_token)
            await self._unit_of_work.commit()

    def _to_token_pair(self, access_token: str, raw_token: str) -> TokenPairDTO:
        return TokenPairDTO(
            access_token=access_token,
            refresh_token=raw_token,
            token_type="Bearer",
            expires_in=self._access_token_expire_minutes * 60,
        )


class RefreshAccessTokenService:
    def __init__(
        self,
        refresh_token_repository: RefreshTokenRepository,
        account_repository: AccountRepository,
        refresh_token_factory: RefreshTokenFactory,
        access_token_service: AccessTokenService,
        token_hasher: TokenHasher,
        clock: Clock,
        unit_of_work: UnitOfWork,
        event_publisher: EventPublisher,
        access_token_expire_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES,
    ) -> None:
        self._refresh_token_repository = refresh_token_repository
        self._account_repository = account_repository
        self._refresh_token_factory = refresh_token_factory
        self._access_token_service = access_token_service
        self._token_hasher = token_hasher
        self._clock = clock
        self._unit_of_work = unit_of_work
        self._event_publisher = event_publisher
        self._access_token_expire_minutes = access_token_expire_minutes

    async def execute(self, dto: RefreshDTO) -> TokenPairDTO:
        old_token = await self._find_refresh_token(dto.refresh_token)
        try:
            self._validate_token(old_token)
        except _ReplayDetectedError:
            await self._revoke_token_family(old_token)
            raise RefreshTokenRevokedError(old_token.token_id.value) from None
        old_token.revoke(self._clock.now())
        account = await self._find_account(old_token)
        raw_token, new_token = self._rotate_token(old_token)
        access_token = self._create_access_token(account)
        await self._persist(old_token, new_token)
        self._publish_events(old_token, new_token)
        return self._to_token_pair(access_token, raw_token)

    async def _find_refresh_token(self, raw_token: str) -> RefreshToken:
        token_hash = self._token_hasher.hash(raw_token)
        token = await self._refresh_token_repository.find_by_token_hash(token_hash)
        if token is None:
            raise RefreshTokenNotFoundError()
        return token

    def _validate_token(self, token: RefreshToken) -> None:
        if token.is_revoked:
            self._handle_replay_detection(token)
        if token.is_expired(self._clock.now()):
            raise RefreshTokenExpiredError(token.token_id.value)

    def _handle_replay_detection(self, token: RefreshToken) -> None:
        raise _ReplayDetectedError(token)

    async def _revoke_token_family(self, token: RefreshToken) -> None:
        async with self._unit_of_work:
            await self._refresh_token_repository.revoke_all_by_family(token.family)
            await self._unit_of_work.commit()
        self._event_publisher.publish(
            [
                RefreshTokenFamilyRevoked(
                    account_id=token.account_id.value,
                    family=token.family.value,
                )
            ]
        )

    async def _find_account(self, token: RefreshToken) -> Account:
        account = await self._account_repository.find_by_id(token.account_id)
        if account is None:
            raise AccountNotFoundError(token.account_id.value)
        return account

    def _rotate_token(self, old_token: RefreshToken) -> tuple[str, RefreshToken]:
        return self._refresh_token_factory.rotate(old_token)

    def _create_access_token(self, account: Account) -> str:
        return self._access_token_service.create_access_token(
            account_id=str(account.account_id.value),
            email=account.email.value,
        )

    async def _persist(self, old_token: RefreshToken, new_token: RefreshToken) -> None:
        async with self._unit_of_work:
            await self._refresh_token_repository.save(old_token)
            await self._refresh_token_repository.save(new_token)
            await self._unit_of_work.commit()

    def _publish_events(self, old_token: RefreshToken, new_token: RefreshToken) -> None:
        events = old_token.collect_events() + new_token.collect_events()
        self._event_publisher.publish(events)

    def _to_token_pair(self, access_token: str, raw_token: str) -> TokenPairDTO:
        return TokenPairDTO(
            access_token=access_token,
            refresh_token=raw_token,
            token_type="Bearer",
            expires_in=self._access_token_expire_minutes * 60,
        )


class _ReplayDetectedError(Exception):
    def __init__(self, token: RefreshToken) -> None:
        self.token = token


class LogoutService:
    def __init__(
        self,
        refresh_token_repository: RefreshTokenRepository,
        token_hasher: TokenHasher,
        clock: Clock,
        unit_of_work: UnitOfWork,
        event_publisher: EventPublisher,
    ) -> None:
        self._refresh_token_repository = refresh_token_repository
        self._token_hasher = token_hasher
        self._clock = clock
        self._unit_of_work = unit_of_work
        self._event_publisher = event_publisher

    async def execute(self, dto: LogoutDTO) -> None:
        refresh_token = await self._find_refresh_token(dto.refresh_token)
        refresh_token.revoke(self._clock.now())
        await self._persist(refresh_token)
        self._event_publisher.publish(refresh_token.collect_events())

    async def _find_refresh_token(self, raw_token: str) -> RefreshToken:
        token_hash = self._token_hasher.hash(raw_token)
        token = await self._refresh_token_repository.find_by_token_hash(token_hash)
        if token is None:
            raise RefreshTokenNotFoundError()
        return token

    async def _persist(self, refresh_token: RefreshToken) -> None:
        async with self._unit_of_work:
            await self._refresh_token_repository.save(refresh_token)
            await self._unit_of_work.commit()
