from datetime import datetime
from uuid import uuid4

import pytest

from pydentity.authentication.domain.recovery_request.aggregate import RecoveryRequest
from pydentity.authentication.domain.recovery_request.aggregate_id import (
    RecoveryRequestId,
)
from pydentity.authentication.domain.recovery_request.value_objects import (
    RecoveryToken,
)
from pydentity.shared_kernel import AccountId


@pytest.fixture
def recovery_request_id() -> RecoveryRequestId:
    return RecoveryRequestId(value=uuid4())


@pytest.fixture
def recovery_token(far_future: datetime) -> RecoveryToken:
    return RecoveryToken(token_hash="$hashed_recovery_token", expires_at=far_future)


@pytest.fixture
def expired_recovery_token(past: datetime) -> RecoveryToken:
    return RecoveryToken(token_hash="$hashed_expired", expires_at=past)


@pytest.fixture
def pending_request(
    recovery_request_id: RecoveryRequestId,
    account_id: AccountId,
    recovery_token: RecoveryToken,
    now: datetime,
) -> RecoveryRequest:
    request = RecoveryRequest.create(
        recovery_request_id, account_id, recovery_token, now
    )
    request.clear_events()
    return request


@pytest.fixture
def verified_request(
    pending_request: RecoveryRequest, now: datetime
) -> RecoveryRequest:
    pending_request.verify(now)
    pending_request.clear_events()
    return pending_request
