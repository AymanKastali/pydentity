from typing import TYPE_CHECKING

from pydentity.domain.base import AggregateRoot
from pydentity.domain.refresh_token.errors import RefreshTokenRevokedError
from pydentity.domain.refresh_token.events import (
    RefreshTokenIssued,
    RefreshTokenRevoked,
)

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.account.aggregate_id import AccountId
    from pydentity.domain.refresh_token.aggregate_id import RefreshTokenId
    from pydentity.domain.refresh_token.value_objects import TokenFamily


class RefreshToken(AggregateRoot):
    def __init__(
        self,
        token_id: RefreshTokenId,
        token_hash: str,
        account_id: AccountId,
        family: TokenFamily,
        expires_at: datetime,
        revoked_at: datetime | None,
    ) -> None:
        super().__init__(token_id.value)
        self._token_id = token_id
        self._token_hash = token_hash
        self._account_id = account_id
        self._family = family
        self._expires_at = expires_at
        self._revoked_at = revoked_at

    @classmethod
    def issue(
        cls,
        token_id: RefreshTokenId,
        token_hash: str,
        account_id: AccountId,
        family: TokenFamily,
        expires_at: datetime,
    ) -> RefreshToken:
        token = cls(
            token_id=token_id,
            token_hash=token_hash,
            account_id=account_id,
            family=family,
            expires_at=expires_at,
            revoked_at=None,
        )
        token._record_event(
            RefreshTokenIssued(
                token_id=token_id.value,
                account_id=account_id.value,
                family=family.value,
            )
        )
        return token

    def revoke(self, now: datetime) -> None:
        self._ensure_not_already_revoked()
        self._revoked_at = now
        self._record_event(
            RefreshTokenRevoked(
                token_id=self._token_id.value,
                account_id=self._account_id.value,
            )
        )

    def is_expired(self, now: datetime) -> bool:
        return self._expires_at < now

    @property
    def is_revoked(self) -> bool:
        return self._revoked_at is not None

    def is_valid(self, now: datetime) -> bool:
        return not self.is_expired(now) and not self.is_revoked

    def _ensure_not_already_revoked(self) -> None:
        if self._revoked_at is not None:
            raise RefreshTokenRevokedError(self._token_id.value)

    @property
    def token_id(self) -> RefreshTokenId:
        return self._token_id

    @property
    def token_hash(self) -> str:
        return self._token_hash

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def family(self) -> TokenFamily:
        return self._family

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def revoked_at(self) -> datetime | None:
        return self._revoked_at
