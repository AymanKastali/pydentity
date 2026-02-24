from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.events.session_events import (
    RefreshTokenReused,
    RefreshTokenRotated,
    SessionEstablished,
    SessionTerminated,
)
from pydentity.domain.models.base import AggregateRoot
from pydentity.domain.models.enums import SessionStatus
from pydentity.domain.models.exceptions import (
    RefreshTokenReuseDetectedError,
    SessionExpiredError,
    SessionRevokedError,
)
from pydentity.domain.models.value_objects import (
    HashedRefreshToken,
    RefreshTokenFamily,
    SessionId,
    UserId,
)

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from pydentity.domain.events.base import DomainEvent


class Session(AggregateRoot):
    def __init__(
        self,
        *,
        session_id: SessionId,
        user_id: UserId,
        refresh_token_hash: HashedRefreshToken,
        refresh_token_family: RefreshTokenFamily,
        status: SessionStatus,
        created_at: datetime,
        last_refreshed_at: datetime,
        expires_at: datetime,
    ) -> None:
        self._id = session_id
        self._user_id = user_id
        self._refresh_token_hash = refresh_token_hash
        self._refresh_token_family = refresh_token_family
        self._status = status
        self._created_at = created_at
        self._last_refreshed_at = last_refreshed_at
        self._expires_at = expires_at
        self._events: list[DomainEvent] = []

    @staticmethod
    def establish(
        session_id: SessionId,
        user_id: UserId,
        initial_refresh_token_hash: HashedRefreshToken,
        absolute_lifetime: timedelta,
        created_at: datetime,
    ) -> Session:
        session = Session(
            session_id=session_id,
            user_id=user_id,
            refresh_token_hash=initial_refresh_token_hash,
            refresh_token_family=RefreshTokenFamily(
                family_id=session_id.value, generation=0
            ),
            status=SessionStatus.ACTIVE,
            created_at=created_at,
            last_refreshed_at=created_at,
            expires_at=created_at + absolute_lifetime,
        )

        session._record_event(
            SessionEstablished(
                session_id=session_id.value,
                user_id=user_id.value,
            )
        )
        return session

    @staticmethod
    def _reconstitute(
        session_id: SessionId,
        user_id: UserId,
        refresh_token_hash: HashedRefreshToken,
        refresh_token_family: RefreshTokenFamily,
        status: SessionStatus,
        created_at: datetime,
        last_refreshed_at: datetime,
        expires_at: datetime,
    ) -> Session:
        return Session(
            session_id=session_id,
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            refresh_token_family=refresh_token_family,
            status=status,
            created_at=created_at,
            last_refreshed_at=last_refreshed_at,
            expires_at=expires_at,
        )

    # --- Read-only properties ---

    @property
    def id(self) -> SessionId:
        return self._id

    @property
    def user_id(self) -> UserId:
        return self._user_id

    @property
    def refresh_token_hash(self) -> HashedRefreshToken:
        return self._refresh_token_hash

    @property
    def refresh_token_family(self) -> RefreshTokenFamily:
        return self._refresh_token_family

    @property
    def status(self) -> SessionStatus:
        return self._status

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def last_refreshed_at(self) -> datetime:
        return self._last_refreshed_at

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    # --- Helpers ---

    def _ensure_active(self, now: datetime) -> None:
        if self._status == SessionStatus.REVOKED:
            raise SessionRevokedError("Session has been revoked")
        if self.is_expired(now):
            raise SessionExpiredError("Session has expired")

    # --- Commands ---

    def rotate_refresh_token(
        self,
        presented_hash: HashedRefreshToken,
        new_hash: HashedRefreshToken,
        now: datetime,
    ) -> None:
        self._ensure_active(now)

        if presented_hash.value != self._refresh_token_hash.value:
            self._status = SessionStatus.REVOKED
            self._record_event(
                RefreshTokenReused(
                    session_id=self._id.value,
                    user_id=self._user_id.value,
                )
            )
            raise RefreshTokenReuseDetectedError(
                "Refresh token reuse detected — session revoked"
            )

        self._refresh_token_hash = new_hash
        self._refresh_token_family = self._refresh_token_family.next_generation()
        self._last_refreshed_at = now

        self._record_event(RefreshTokenRotated(session_id=self._id.value))

    def revoke(self) -> None:
        if self._status == SessionStatus.REVOKED:
            return

        self._status = SessionStatus.REVOKED

        self._record_event(SessionTerminated(session_id=self._id.value))

    def is_expired(self, now: datetime) -> bool:
        return now >= self._expires_at
