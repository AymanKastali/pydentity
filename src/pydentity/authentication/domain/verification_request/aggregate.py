from datetime import datetime
from typing import Self

from pydentity.authentication.domain.verification_request.errors import (
    VerificationRequestNotPendingError,
)
from pydentity.authentication.domain.verification_request.events import (
    VerificationRequestCreated,
    VerificationRequestExpired,
    VerificationRequestInvalidated,
    VerificationRequestVerified,
)
from pydentity.authentication.domain.verification_request.value_objects import (
    HashedVerificationRequestToken,
    VerificationRequestExpiry,
    VerificationRequestId,
    VerificationRequestStatus,
    VerificationRequestType,
)
from pydentity.shared_kernel.building_blocks import AggregateRoot
from pydentity.shared_kernel.value_objects import AccountId


class VerificationRequest(AggregateRoot[VerificationRequestId]):
    def __init__(
        self,
        verification_request_id: VerificationRequestId,
        account_id: AccountId,
        status: VerificationRequestStatus,
        request_type: VerificationRequestType,
        hashed_token: HashedVerificationRequestToken,
        expiry: VerificationRequestExpiry,
    ) -> None:
        super().__init__(verification_request_id)
        self._account_id: AccountId = account_id
        self._status: VerificationRequestStatus = status
        self._request_type: VerificationRequestType = request_type
        self._hashed_token: HashedVerificationRequestToken = hashed_token
        self._expiry: VerificationRequestExpiry = expiry

    @classmethod
    def create(
        cls,
        verification_request_id: VerificationRequestId,
        account_id: AccountId,
        request_type: VerificationRequestType,
        hashed_token: HashedVerificationRequestToken,
        expiry: VerificationRequestExpiry,
    ) -> Self:
        request = cls(
            verification_request_id=verification_request_id,
            account_id=account_id,
            status=VerificationRequestStatus.PENDING,
            request_type=request_type,
            hashed_token=hashed_token,
            expiry=expiry,
        )
        request._record_verification_request_created()
        return request

    def verify(self) -> None:
        self._guard_status_is_pending()
        self._mark_as_verified()
        self._record_verification_request_verified()

    def invalidate(self) -> None:
        self._guard_status_is_pending()
        self._mark_as_invalidated()
        self._record_verification_request_invalidated()

    def expire(self) -> None:
        self._guard_status_is_pending()
        self._mark_as_expired()
        self._record_verification_request_expired()

    def is_expired_at(self, current_time: datetime) -> bool:
        return current_time >= self._expiry.value

    def _mark_as_verified(self) -> None:
        self._status = VerificationRequestStatus.VERIFIED

    def _mark_as_invalidated(self) -> None:
        self._status = VerificationRequestStatus.INVALIDATED

    def _mark_as_expired(self) -> None:
        self._status = VerificationRequestStatus.EXPIRED

    def _guard_status_is_pending(self) -> None:
        if self._status is not VerificationRequestStatus.PENDING:
            raise VerificationRequestNotPendingError(self._status)

    def _record_verification_request_created(self) -> None:
        self.record_event(
            VerificationRequestCreated(
                verification_request_id=self._id,
                account_id=self._account_id,
                request_type=self._request_type,
            )
        )

    def _record_verification_request_verified(self) -> None:
        self.record_event(
            VerificationRequestVerified(
                verification_request_id=self._id, account_id=self._account_id
            )
        )

    def _record_verification_request_invalidated(self) -> None:
        self.record_event(
            VerificationRequestInvalidated(
                verification_request_id=self._id, account_id=self._account_id
            )
        )

    def _record_verification_request_expired(self) -> None:
        self.record_event(
            VerificationRequestExpired(
                verification_request_id=self._id, account_id=self._account_id
            )
        )

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def status(self) -> VerificationRequestStatus:
        return self._status

    @property
    def request_type(self) -> VerificationRequestType:
        return self._request_type

    @property
    def hashed_token(self) -> HashedVerificationRequestToken:
        return self._hashed_token

    @property
    def expiry(self) -> VerificationRequestExpiry:
        return self._expiry
