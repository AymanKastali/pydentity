from datetime import datetime
from uuid import uuid4

import pytest

from pydentity.authentication.domain.recovery_request.aggregate import RecoveryRequest
from pydentity.authentication.domain.recovery_request.aggregate_id import (
    RecoveryRequestId,
)
from pydentity.authentication.domain.recovery_request.errors import (
    RecoveryRequestAlreadyCompletedError,
    RecoveryRequestAlreadyExpiredError,
    RecoveryRequestNotPendingError,
    RecoveryRequestNotVerifiedError,
    RecoveryTokenExpiredError,
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
from pydentity.shared_kernel import AccountId

# --- Factory ---


class TestRecoveryRequestCreate:
    def test_creates_pending_request(
        self,
        recovery_request_id: RecoveryRequestId,
        account_id: AccountId,
        recovery_token: RecoveryToken,
        now: datetime,
    ):
        request = RecoveryRequest.create(
            recovery_request_id, account_id, recovery_token, now
        )
        assert request.status == RecoveryRequestStatus.PENDING

    def test_records_password_reset_requested_event(
        self,
        recovery_request_id: RecoveryRequestId,
        account_id: AccountId,
        recovery_token: RecoveryToken,
        now: datetime,
    ):
        request = RecoveryRequest.create(
            recovery_request_id, account_id, recovery_token, now
        )
        assert isinstance(request.events[0], PasswordResetRequested)

    def test_records_recovery_token_issued_event(
        self,
        recovery_request_id: RecoveryRequestId,
        account_id: AccountId,
        recovery_token: RecoveryToken,
        now: datetime,
    ):
        request = RecoveryRequest.create(
            recovery_request_id, account_id, recovery_token, now
        )
        assert isinstance(request.events[1], RecoveryTokenIssued)

    def test_stores_account_id(
        self,
        recovery_request_id: RecoveryRequestId,
        account_id: AccountId,
        recovery_token: RecoveryToken,
        now: datetime,
    ):
        request = RecoveryRequest.create(
            recovery_request_id, account_id, recovery_token, now
        )
        assert request.account_id == account_id

    def test_stores_recovery_token(
        self,
        recovery_request_id: RecoveryRequestId,
        account_id: AccountId,
        recovery_token: RecoveryToken,
        now: datetime,
    ):
        request = RecoveryRequest.create(
            recovery_request_id, account_id, recovery_token, now
        )
        assert request.recovery_token == recovery_token


# --- Verify ---


class TestRecoveryRequestVerify:
    def test_transitions_to_verified(
        self,
        pending_request: RecoveryRequest,
        now: datetime,
    ):
        pending_request.verify(now)
        assert pending_request.status == RecoveryRequestStatus.VERIFIED

    def test_records_recovery_token_verified_event(
        self,
        pending_request: RecoveryRequest,
        now: datetime,
    ):
        pending_request.verify(now)
        assert isinstance(pending_request.events[0], RecoveryTokenVerified)

    def test_raises_when_not_pending(
        self,
        verified_request: RecoveryRequest,
        now: datetime,
    ):
        with pytest.raises(RecoveryRequestNotPendingError):
            verified_request.verify(now)

    def test_raises_when_token_expired(
        self,
        account_id: AccountId,
        expired_recovery_token: RecoveryToken,
        now: datetime,
    ):
        request_id = RecoveryRequestId(value=uuid4())
        request = RecoveryRequest.create(
            request_id, account_id, expired_recovery_token, now
        )
        request.clear_events()
        with pytest.raises(RecoveryTokenExpiredError):
            request.verify(now)


# --- Complete ---


class TestRecoveryRequestComplete:
    def test_transitions_to_completed(
        self,
        verified_request: RecoveryRequest,
        now: datetime,
    ):
        verified_request.complete(now)
        assert verified_request.status == RecoveryRequestStatus.COMPLETED

    def test_records_recovery_request_completed_event(
        self,
        verified_request: RecoveryRequest,
        now: datetime,
    ):
        verified_request.complete(now)
        assert isinstance(verified_request.events[0], RecoveryRequestCompleted)

    def test_raises_when_not_verified(
        self,
        pending_request: RecoveryRequest,
        now: datetime,
    ):
        with pytest.raises(RecoveryRequestNotVerifiedError):
            pending_request.complete(now)


# --- Expire ---


class TestRecoveryRequestExpire:
    def test_transitions_to_expired(
        self,
        pending_request: RecoveryRequest,
        now: datetime,
    ):
        pending_request.expire(now)
        assert pending_request.status == RecoveryRequestStatus.EXPIRED

    def test_records_password_reset_expired_event(
        self,
        pending_request: RecoveryRequest,
        now: datetime,
    ):
        pending_request.expire(now)
        assert isinstance(pending_request.events[0], PasswordResetExpired)

    def test_raises_when_already_completed(
        self,
        verified_request: RecoveryRequest,
        now: datetime,
    ):
        verified_request.complete(now)
        verified_request.clear_events()
        with pytest.raises(RecoveryRequestAlreadyCompletedError):
            verified_request.expire(now)

    def test_raises_when_already_expired(
        self,
        pending_request: RecoveryRequest,
        now: datetime,
    ):
        pending_request.expire(now)
        pending_request.clear_events()
        with pytest.raises(RecoveryRequestAlreadyExpiredError):
            pending_request.expire(now)

    def test_succeeds_from_pending(
        self,
        pending_request: RecoveryRequest,
        now: datetime,
    ):
        pending_request.expire(now)
        assert pending_request.status == RecoveryRequestStatus.EXPIRED

    def test_succeeds_from_verified(
        self,
        verified_request: RecoveryRequest,
        now: datetime,
    ):
        verified_request.expire(now)
        assert verified_request.status == RecoveryRequestStatus.EXPIRED
