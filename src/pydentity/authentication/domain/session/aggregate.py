from datetime import datetime, timedelta
from typing import Self

from pydentity.authentication.domain.session.errors import SessionNotActiveError
from pydentity.authentication.domain.session.events import (
    SessionRefreshed,
    SessionRevoked,
    SessionStarted,
)
from pydentity.authentication.domain.session.value_objects import (
    SessionExpiry,
    SessionId,
    SessionPolicy,
    SessionRevocationReason,
    SessionStatus,
)
from pydentity.shared_kernel.building_blocks import AggregateRoot
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


class Session(AggregateRoot[SessionId]):
    def __init__(
        self,
        session_id: SessionId,
        account_id: AccountId,
        device_id: DeviceId,
        status: SessionStatus,
        expiry: SessionExpiry,
    ) -> None:
        super().__init__(session_id)
        self._account_id: AccountId = account_id
        self._device_id: DeviceId = device_id
        self._status: SessionStatus = status
        self._expiry: SessionExpiry = expiry

    @classmethod
    def create(
        cls,
        session_id: SessionId,
        account_id: AccountId,
        device_id: DeviceId,
        expiry: SessionExpiry,
    ) -> Self:
        session = cls(
            session_id=session_id,
            account_id=account_id,
            device_id=device_id,
            status=SessionStatus.ACTIVE,
            expiry=expiry,
        )
        session._record_session_started()
        return session

    def revoke(self, reason: SessionRevocationReason) -> None:
        self._guard_status_is_active()
        self._mark_as_revoked()
        self._record_session_revoked(reason)

    def refresh(self, policy: SessionPolicy, current_time: datetime) -> None:
        self._guard_status_is_active()
        self._compute_expiry(policy, current_time)
        self._record_session_refreshed()

    def _compute_expiry(self, policy: SessionPolicy, current_time: datetime) -> None:
        self._expiry = SessionExpiry(
            value=current_time + timedelta(seconds=policy.ttl_seconds),
        )

    def _mark_as_revoked(self) -> None:
        self._status = SessionStatus.REVOKED

    def _guard_status_is_active(self) -> None:
        if self._status is not SessionStatus.ACTIVE:
            raise SessionNotActiveError(self._status)

    def _record_session_started(self) -> None:
        self.record_event(
            SessionStarted(
                session_id=self._id,
                account_id=self._account_id,
                device_id=self._device_id,
            )
        )

    def _record_session_revoked(self, reason: SessionRevocationReason) -> None:
        self.record_event(
            SessionRevoked(
                session_id=self._id,
                account_id=self._account_id,
                device_id=self._device_id,
                reason=reason,
            )
        )

    def _record_session_refreshed(self) -> None:
        self.record_event(
            SessionRefreshed(
                session_id=self._id,
                account_id=self._account_id,
                device_id=self._device_id,
            )
        )

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def device_id(self) -> DeviceId:
        return self._device_id

    @property
    def status(self) -> SessionStatus:
        return self._status

    @property
    def expiry(self) -> SessionExpiry:
        return self._expiry
