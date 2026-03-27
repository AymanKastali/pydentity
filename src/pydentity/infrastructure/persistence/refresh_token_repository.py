from typing import TYPE_CHECKING

from sqlmodel import col, select, update

from pydentity.domain.account.aggregate_id import AccountId
from pydentity.domain.refresh_token.aggregate import RefreshToken
from pydentity.domain.refresh_token.aggregate_id import RefreshTokenId
from pydentity.domain.refresh_token.repository import RefreshTokenRepository
from pydentity.domain.refresh_token.value_objects import TokenFamily
from pydentity.infrastructure.persistence.models import RefreshTokenModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from pydentity.application.services.clock import Clock


class SqlAlchemyRefreshTokenRepository(RefreshTokenRepository):
    def __init__(self, session: AsyncSession, clock: Clock) -> None:
        self._session = session
        self._clock = clock

    async def find_by_token_hash(self, token_hash: str) -> RefreshToken | None:
        statement = select(RefreshTokenModel).where(
            RefreshTokenModel.token_hash == token_hash
        )
        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return self._to_domain(model)

    async def save(self, refresh_token: RefreshToken) -> None:
        model = RefreshTokenModel(
            id=refresh_token.token_id.value,
            token_hash=refresh_token.token_hash,
            account_id=refresh_token.account_id.value,
            family=refresh_token.family.value,
            expires_at=refresh_token.expires_at,
            revoked_at=refresh_token.revoked_at,
            created_at=self._clock.now(),
        )
        await self._session.merge(model)

    async def revoke_all_by_family(self, family: TokenFamily) -> None:
        statement = (
            update(RefreshTokenModel)
            .where(col(RefreshTokenModel.family) == family.value)
            .where(col(RefreshTokenModel.revoked_at).is_(None))
            .values(revoked_at=self._clock.now())
        )
        await self._session.execute(statement)

    async def revoke_all_by_account_id(self, account_id: AccountId) -> None:
        statement = (
            update(RefreshTokenModel)
            .where(col(RefreshTokenModel.account_id) == account_id.value)
            .where(col(RefreshTokenModel.revoked_at).is_(None))
            .values(revoked_at=self._clock.now())
        )
        await self._session.execute(statement)

    @classmethod
    def _to_domain(cls, model: RefreshTokenModel) -> RefreshToken:
        return RefreshToken(
            token_id=RefreshTokenId(model.id),
            token_hash=model.token_hash,
            account_id=AccountId(model.account_id),
            family=TokenFamily(model.family),
            expires_at=model.expires_at,
            revoked_at=model.revoked_at,
        )
