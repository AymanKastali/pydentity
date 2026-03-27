from typing import TYPE_CHECKING

from sqlmodel import select

from pydentity.domain.account.aggregate import Account
from pydentity.domain.account.aggregate_id import AccountId
from pydentity.domain.account.repository import AccountRepository
from pydentity.domain.account.value_objects import (
    AccountStatus,
    Email,
    HashedPassword,
    VerificationToken,
)
from pydentity.infrastructure.persistence.models import AccountModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from pydentity.application.services.clock import Clock


class SqlAlchemyAccountRepository(AccountRepository):
    def __init__(self, session: AsyncSession, clock: Clock) -> None:
        self._session = session
        self._clock = clock

    async def find_by_id(self, account_id: AccountId) -> Account | None:
        statement = select(AccountModel).where(AccountModel.id == account_id.value)
        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return self._to_domain(model)

    async def find_by_email(self, email: Email) -> Account | None:
        statement = select(AccountModel).where(AccountModel.email == email.value)
        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return self._to_domain(model)

    async def save(self, account: Account) -> None:
        now = self._clock.now()
        existing = await self._session.get(AccountModel, account.account_id.value)
        if existing is None:
            model = AccountModel(
                id=account.account_id.value,
                email=account.email.value,
                hashed_password=account.hashed_password.value,
                status=account.status.value,
                verification_token=(
                    account.verification_token.value
                    if account.verification_token
                    else None
                ),
                verified_at=None,
                created_at=now,
                updated_at=now,
            )
            self._session.add(model)
        else:
            existing.email = account.email.value
            existing.hashed_password = account.hashed_password.value
            existing.status = account.status.value
            existing.verification_token = (
                account.verification_token.value if account.verification_token else None
            )
            if account.status == AccountStatus.ACTIVE and existing.verified_at is None:
                existing.verified_at = now
            existing.updated_at = now

    @classmethod
    def _to_domain(cls, model: AccountModel) -> Account:
        verification_token = (
            VerificationToken(model.verification_token)
            if model.verification_token
            else None
        )
        return Account(
            account_id=AccountId(model.id),
            email=Email(model.email),
            hashed_password=HashedPassword(model.hashed_password),
            status=AccountStatus(model.status),
            verification_token=verification_token,
        )
