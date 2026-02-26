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
    InvalidValueError,
    RefreshTokenReuseDetectedError,
    SessionExpiredError,
    SessionRevokedError,
)
from pydentity.domain.models.value_objects import (
    HashedRefreshToken,
    RefreshTokenFamily,
    SessionCreatedAt,
    SessionExpiry,
    SessionId,
    SessionLastRefresh,
    UserId,
)

if TYPE_CHECKING:
    from datetime import datetime, timedelta


class Session(AggregateRoot[SessionId]):
    def __init__(
        self,
        *,
        session_id: SessionId,
        user_id: UserId,
        refresh_token_hash: HashedRefreshToken,
        refresh_token_family: RefreshTokenFamily,
        status: SessionStatus,
        created_at: SessionCreatedAt,
        last_refresh: SessionLastRefresh,
        expiry: SessionExpiry,
    ) -> None:
        super().__init__()
        self._id = session_id
        self._user_id = user_id
        self._refresh_token_hash = refresh_token_hash
        self._refresh_token_family = refresh_token_family
        self._status = status
        self._created_at = created_at
        self._last_refresh = last_refresh
        self._expiry = expiry

    @classmethod
    def establish(
        cls,
        session_id: SessionId,
        user_id: UserId,
        initial_refresh_token_hash: HashedRefreshToken,
        absolute_lifetime: timedelta,
        created_at: datetime,
    ) -> Session:
        if absolute_lifetime.total_seconds() <= 0:
            raise InvalidValueError(
                field_name="absolute_lifetime",
                reason="must be positive",
            )

        session = cls(
            session_id=session_id,
            user_id=user_id,
            refresh_token_hash=initial_refresh_token_hash,
            refresh_token_family=RefreshTokenFamily(
                family_id=session_id.value, generation=0
            ),
            status=SessionStatus.ACTIVE,
            created_at=SessionCreatedAt(created_at=created_at),
            last_refresh=SessionLastRefresh(refreshed_at=created_at),
            expiry=SessionExpiry(
                expires_at=created_at + absolute_lifetime,
            ),
        )

        session._record_event(
            SessionEstablished(
                session_id=session_id.value,
                user_id=user_id.value,
            )
        )
        return session

    @classmethod
    def _reconstitute(
        cls,
        session_id: SessionId,
        user_id: UserId,
        refresh_token_hash: HashedRefreshToken,
        refresh_token_family: RefreshTokenFamily,
        status: SessionStatus,
        created_at: SessionCreatedAt,
        last_refresh: SessionLastRefresh,
        expiry: SessionExpiry,
    ) -> Session:
        return cls(
            session_id=session_id,
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            refresh_token_family=refresh_token_family,
            status=status,
            created_at=created_at,
            last_refresh=last_refresh,
            expiry=expiry,
        )

    # --- Read-only properties ---

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
    def created_at(self) -> SessionCreatedAt:
        return self._created_at

    @property
    def last_refresh(self) -> SessionLastRefresh:
        return self._last_refresh

    @property
    def expiry(self) -> SessionExpiry:
        return self._expiry

    # --- Helpers ---

    def _ensure_active(self, now: datetime) -> None:
        if self._status == SessionStatus.REVOKED:
            raise SessionRevokedError()
        if self.is_expired(now):
            raise SessionExpiredError()

    # --- Commands ---

    def rotate_refresh_token(
        self,
        presented_hash: HashedRefreshToken,
        new_hash: HashedRefreshToken,
        now: datetime,
    ) -> None:
        self._ensure_active(now)

        if not self._refresh_token_hash.timing_safe_equals(presented_hash):
            self._status = SessionStatus.REVOKED
            self._record_event(
                RefreshTokenReused(
                    session_id=self._id.value,
                    user_id=self._user_id.value,
                )
            )
            raise RefreshTokenReuseDetectedError()

        self._refresh_token_hash = new_hash
        self._refresh_token_family = self._refresh_token_family.next_generation()
        self._last_refresh = SessionLastRefresh(refreshed_at=now)

        self._record_event(RefreshTokenRotated(session_id=self._id.value))

    def revoke(self) -> None:
        if self._status == SessionStatus.REVOKED:
            return

        self._status = SessionStatus.REVOKED

        self._record_event(SessionTerminated(session_id=self._id.value))

    def is_expired(self, now: datetime) -> bool:
        return self._expiry.is_expired(now)
