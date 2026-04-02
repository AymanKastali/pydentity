from typing import TYPE_CHECKING

from pydentity.authentication.domain.recovery_request.aggregate_id import (
    RecoveryRequestId,
)
from pydentity.authentication.domain.recovery_request.events import (
    PasswordResetExpired,
    PasswordResetRequested,
    RecoveryRequestCompleted,
    RecoveryTokenIssued,
    RecoveryTokenVerified,
)
from pydentity.authentication.domain.recovery_request.value_objects import (
    RecoveryRequestStatus,
    RecoveryToken,
)
from pydentity.shared_kernel import AggregateRoot

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.shared_kernel import AccountId


class RecoveryRequest(AggregateRoot[RecoveryRequestId]):
    def __init__(
        self,
        request_id: RecoveryRequestId,
        account_id: AccountId,
        recovery_token: RecoveryToken,
        status: RecoveryRequestStatus,
    ) -> None:
        super().__init__(request_id)
        self._account_id: AccountId = account_id
        self._recovery_token: RecoveryToken = recovery_token
        self._status: RecoveryRequestStatus = status

    # --- Creation ---

    @classmethod
    def create(
        cls,
        request_id: RecoveryRequestId,
        account_id: AccountId,
        recovery_token: RecoveryToken,
        now: datetime,
    ) -> RecoveryRequest:
        request = cls(
            request_id=request_id,
            account_id=account_id,
            recovery_token=recovery_token,
            status=RecoveryRequestStatus.PENDING,
        )
        request.record_event(
            PasswordResetRequested(
                occurred_at=now, request_id=request_id, account_id=account_id
            )
        )
        request.record_event(
            RecoveryTokenIssued(
                occurred_at=now, request_id=request_id, account_id=account_id
            )
        )
        return request

    # --- Queries ---

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def recovery_token(self) -> RecoveryToken:
        return self._recovery_token

    @property
    def status(self) -> RecoveryRequestStatus:
        return self._status

    # --- Token verification ---

    def verify(self, now: datetime) -> None:
        self._status.guard_is_pending()
        self._recovery_token.guard_not_expired(now)
        self._mark_verified()
        self.record_event(
            RecoveryTokenVerified(
                occurred_at=now, request_id=self._id, account_id=self._account_id
            )
        )

    def _mark_verified(self) -> None:
        self._status = RecoveryRequestStatus.VERIFIED

    # --- Completion ---

    def complete(self, now: datetime) -> None:
        self._status.guard_is_verified()
        self._mark_completed()
        self.record_event(
            RecoveryRequestCompleted(
                occurred_at=now,
                request_id=self._id,
                account_id=self._account_id,
            )
        )

    def _mark_completed(self) -> None:
        self._status = RecoveryRequestStatus.COMPLETED

    # --- Expiration ---

    def expire(self, now: datetime) -> None:
        self._status.guard_not_completed()
        self._status.guard_not_expired()
        self._mark_expired()
        self.record_event(
            PasswordResetExpired(
                occurred_at=now,
                request_id=self._id,
                account_id=self._account_id,
            )
        )

    def _mark_expired(self) -> None:
        self._status = RecoveryRequestStatus.EXPIRED
