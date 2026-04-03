from typing import TYPE_CHECKING

from pydentity.authentication.domain.session.aggregate_id import SessionId
from pydentity.authentication.domain.session.events import (
    RefreshTokenRotated,
    SessionEnded,
    SessionStarted,
)
from pydentity.authentication.domain.session.value_objects import (
    RefreshToken,
    SessionEndReason,
    SessionStatus,
)
from pydentity.shared_kernel import AggregateRoot

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.shared_kernel import AccountId


class Session(AggregateRoot[SessionId]):
    def __init__(
        self,
        session_id: SessionId,
        account_id: AccountId,
        refresh_token: RefreshToken,
        status: SessionStatus,
    ) -> None:
        super().__init__(session_id)
        self._account_id: AccountId = account_id
        self._refresh_token: RefreshToken = refresh_token
        self._status: SessionStatus = status

    # --- Creation ---

    @classmethod
    def start(
        cls,
        session_id: SessionId,
        account_id: AccountId,
        refresh_token: RefreshToken,
        now: datetime,
    ) -> Session:
        session = cls(
            session_id=session_id,
            account_id=account_id,
            refresh_token=refresh_token,
            status=SessionStatus.ACTIVE,
        )
        session.record_event(
            SessionStarted(
                occurred_at=now, session_id=session_id, account_id=account_id
            )
        )
        return session

    # --- Queries ---

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def refresh_token(self) -> RefreshToken:
        return self._refresh_token

    @property
    def status(self) -> SessionStatus:
        return self._status

    # --- Token refresh ---

    def refresh(self, new_refresh_token: RefreshToken, now: datetime) -> None:
        self._status.guard_is_active()
        self._refresh_token.guard_not_expired(now)
        self._refresh_token.guard_not_revoked()
        self._rotate_refresh_token(new_refresh_token)
        self.record_event(
            RefreshTokenRotated(
                occurred_at=now,
                session_id=self._id,
                account_id=self._account_id,
            )
        )

    def _rotate_refresh_token(self, new_refresh_token: RefreshToken) -> None:
        self._refresh_token = new_refresh_token

    # --- Termination ---

    def end(self, now: datetime) -> None:
        self._terminate(SessionEndReason.LOGOUT, now)

    def _terminate(self, reason: SessionEndReason, now: datetime) -> None:
        self._status.guard_is_active()
        self._mark_ended()
        self.record_event(
            SessionEnded(
                occurred_at=now,
                session_id=self._id,
                account_id=self._account_id,
                reason=reason,
            )
        )

    def _mark_ended(self) -> None:
        self._status = SessionStatus.ENDED

    def idle_timeout(self, now: datetime) -> None:
        self._terminate(SessionEndReason.IDLE_TIMEOUT, now)

    def absolute_timeout(self, now: datetime) -> None:
        self._terminate(SessionEndReason.ABSOLUTE_TIMEOUT, now)

    def force_end(self, now: datetime) -> None:
        self._terminate(SessionEndReason.FORCED, now)

    def flag_compromised(self, now: datetime) -> None:
        self._terminate(SessionEndReason.COMPROMISE, now)
