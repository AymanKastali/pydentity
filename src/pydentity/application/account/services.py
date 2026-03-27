from typing import TYPE_CHECKING
from uuid import UUID

from pydentity.application.account.dtos import (
    AccountDTO,
    GetCurrentAccountDTO,
    RegisterAccountDTO,
    RegisterAccountResultDTO,
    VerifyEmailDTO,
)
from pydentity.domain.account.aggregate_id import AccountId
from pydentity.domain.account.errors import (
    AccountAlreadyExistsError,
    AccountNotFoundError,
)
from pydentity.domain.account.value_objects import Email, VerificationToken

if TYPE_CHECKING:
    from pydentity.application.services.event_publisher import EventPublisher
    from pydentity.application.services.unit_of_work import UnitOfWork
    from pydentity.domain.account.aggregate import Account
    from pydentity.domain.account.factory import AccountFactory
    from pydentity.domain.account.repository import AccountRepository


class RegisterAccountService:
    def __init__(
        self,
        account_repository: AccountRepository,
        account_factory: AccountFactory,
        unit_of_work: UnitOfWork,
        event_publisher: EventPublisher,
    ) -> None:
        self._account_repository = account_repository
        self._account_factory = account_factory
        self._unit_of_work = unit_of_work
        self._event_publisher = event_publisher

    async def execute(self, dto: RegisterAccountDTO) -> RegisterAccountResultDTO:
        email = Email(dto.email)
        await self._ensure_email_not_taken(email)
        account = self._account_factory.register(email, dto.password)
        await self._persist(account)
        self._event_publisher.publish(account.collect_events())
        return self._to_result(account)

    async def _ensure_email_not_taken(self, email: Email) -> None:
        existing = await self._account_repository.find_by_email(email)
        if existing is not None:
            raise AccountAlreadyExistsError(email.value)

    async def _persist(self, account: Account) -> None:
        async with self._unit_of_work:
            await self._account_repository.save(account)
            await self._unit_of_work.commit()

    @classmethod
    def _to_result(cls, account: Account) -> RegisterAccountResultDTO:
        return RegisterAccountResultDTO(
            id=str(account.account_id.value),
            email=account.email.value,
            status=account.status.value,
        )


class VerifyEmailService:
    def __init__(
        self,
        account_repository: AccountRepository,
        unit_of_work: UnitOfWork,
        event_publisher: EventPublisher,
    ) -> None:
        self._account_repository = account_repository
        self._unit_of_work = unit_of_work
        self._event_publisher = event_publisher

    async def execute(self, dto: VerifyEmailDTO) -> None:
        account = await self._find_account(dto.account_id)
        account.verify_email(VerificationToken(dto.token))
        await self._persist(account)
        self._event_publisher.publish(account.collect_events())

    async def _find_account(self, raw_id: str) -> Account:
        account_id = AccountId(UUID(raw_id))
        account = await self._account_repository.find_by_id(account_id)
        if account is None:
            raise AccountNotFoundError(account_id.value)
        return account

    async def _persist(self, account: Account) -> None:
        async with self._unit_of_work:
            await self._account_repository.save(account)
            await self._unit_of_work.commit()


class GetCurrentAccountService:
    def __init__(
        self,
        account_repository: AccountRepository,
    ) -> None:
        self._account_repository = account_repository

    async def execute(self, dto: GetCurrentAccountDTO) -> AccountDTO:
        account = await self._find_account(dto.account_id)
        return self._to_dto(account)

    async def _find_account(self, raw_id: str) -> Account:
        account_id = AccountId(UUID(raw_id))
        account = await self._account_repository.find_by_id(account_id)
        if account is None:
            raise AccountNotFoundError(account_id.value)
        return account

    @classmethod
    def _to_dto(cls, account: Account) -> AccountDTO:
        return AccountDTO(
            id=str(account.account_id.value),
            email=account.email.value,
            status=account.status.value,
        )
