from datetime import datetime
from uuid import uuid4

import pytest

from pydentity.authentication.domain.authentication_attempt.aggregate import (
    AuthenticationAttempt,
)
from pydentity.authentication.domain.authentication_attempt.aggregate_id import (
    AuthAttemptId,
)
from pydentity.authentication.domain.authentication_attempt.value_objects import (
    AuthenticationFactor,
    HashedVerificationCode,
    RequiredFactors,
    VerificationCode,
)
from pydentity.shared_kernel import AccountId


@pytest.fixture
def attempt_id() -> AuthAttemptId:
    return AuthAttemptId(value=uuid4())


@pytest.fixture
def knowledge_only_factors() -> RequiredFactors:
    return RequiredFactors(factors=(AuthenticationFactor.KNOWLEDGE,))


@pytest.fixture
def mfa_factors() -> RequiredFactors:
    return RequiredFactors(
        factors=(AuthenticationFactor.KNOWLEDGE, AuthenticationFactor.POSSESSION)
    )


@pytest.fixture
def verification_code(far_future: datetime) -> VerificationCode:
    return VerificationCode(
        hashed_value=HashedVerificationCode(value="$hashed_code"),
        expires_at=far_future,
    )


@pytest.fixture
def in_progress_attempt(
    attempt_id: AuthAttemptId,
    account_id: AccountId,
    mfa_factors: RequiredFactors,
    far_future: datetime,
) -> AuthenticationAttempt:
    return AuthenticationAttempt.initiate(
        attempt_id, account_id, mfa_factors, far_future
    )


@pytest.fixture
def knowledge_only_attempt(
    attempt_id: AuthAttemptId,
    account_id: AccountId,
    knowledge_only_factors: RequiredFactors,
    far_future: datetime,
) -> AuthenticationAttempt:
    return AuthenticationAttempt.initiate(
        attempt_id, account_id, knowledge_only_factors, far_future
    )
