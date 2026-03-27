from datetime import timedelta
from typing import TYPE_CHECKING

from pydentity.domain.refresh_token.aggregate import RefreshToken
from pydentity.domain.refresh_token.aggregate_id import RefreshTokenId
from pydentity.domain.refresh_token.factory import RefreshTokenFactory
from pydentity.domain.refresh_token.value_objects import TokenFamily

if TYPE_CHECKING:
    from pydentity.application.services.clock import Clock
    from pydentity.application.services.id_generator import IdGenerator
    from pydentity.application.services.token_generator import TokenGenerator
    from pydentity.application.services.token_hasher import TokenHasher
    from pydentity.domain.account.aggregate_id import AccountId


class DefaultRefreshTokenFactory(RefreshTokenFactory):
    def __init__(
        self,
        id_generator: IdGenerator,
        token_generator: TokenGenerator,
        token_hasher: TokenHasher,
        clock: Clock,
        expire_days: int,
    ) -> None:
        self._id_generator = id_generator
        self._token_generator = token_generator
        self._token_hasher = token_hasher
        self._clock = clock
        self._expire_days = expire_days

    def issue(self, account_id: AccountId) -> tuple[str, RefreshToken]:
        raw_token = self._token_generator.generate()
        refresh_token = RefreshToken.issue(
            token_id=RefreshTokenId(self._id_generator.generate()),
            token_hash=self._token_hasher.hash(raw_token),
            account_id=account_id,
            family=TokenFamily(self._id_generator.generate()),
            expires_at=self._clock.now() + timedelta(days=self._expire_days),
        )
        return raw_token, refresh_token

    def rotate(self, old_token: RefreshToken) -> tuple[str, RefreshToken]:
        raw_token = self._token_generator.generate()
        new_token = RefreshToken.issue(
            token_id=RefreshTokenId(self._id_generator.generate()),
            token_hash=self._token_hasher.hash(raw_token),
            account_id=old_token.account_id,
            family=old_token.family,
            expires_at=self._clock.now() + timedelta(days=self._expire_days),
        )
        return raw_token, new_token
