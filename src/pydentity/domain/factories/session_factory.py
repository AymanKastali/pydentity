from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.session import Session
from pydentity.domain.models.value_objects import HashedRefreshToken

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from pydentity.domain.models.value_objects import UserId
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort
    from pydentity.domain.ports.token_hasher import TokenHasherPort


class SessionFactory:
    def __init__(
        self,
        *,
        token_hasher: TokenHasherPort,
        identity_generator: IdentityGeneratorPort,
    ) -> None:
        self._token_hasher = token_hasher
        self._identity_generator = identity_generator

    def create(
        self,
        *,
        user_id: UserId,
        raw_refresh_token: str,
        absolute_lifetime: timedelta,
        created_at: datetime,
    ) -> Session:
        session_id = self._identity_generator.new_session_id()
        initial_hash = HashedRefreshToken(
            value=self._token_hasher.hash(raw_refresh_token)
        )
        return Session.create(
            session_id=session_id,
            user_id=user_id,
            initial_refresh_token_hash=initial_hash,
            absolute_lifetime=absolute_lifetime,
            created_at=created_at,
        )
