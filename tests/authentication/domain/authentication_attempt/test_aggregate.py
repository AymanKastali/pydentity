from datetime import datetime, timedelta

import pytest

from pydentity.authentication.domain.authentication_attempt.aggregate import (
    AuthenticationAttempt,
)
from pydentity.authentication.domain.authentication_attempt.aggregate_id import (
    AuthAttemptId,
)
from pydentity.authentication.domain.authentication_attempt.errors import (
    AttemptExpiredError,
    AttemptNotExpiredError,
    AttemptNotInProgressError,
    FactorAlreadyVerifiedError,
    FactorNotRequiredError,
    VerificationCodeAlreadyGeneratedError,
)
from pydentity.authentication.domain.authentication_attempt.events import (
    AuthenticationFailed,
    AuthenticationSucceeded,
    VerificationCodeGenerated,
)
from pydentity.authentication.domain.authentication_attempt.value_objects import (
    AttemptStatus,
    AuthenticationFactor,
    HashedVerificationCode,
    RequiredFactors,
    VerificationCode,
)
from pydentity.shared_kernel import AccountId

# --- Factory ---


class TestAuthenticationAttemptInitiate:
    def test_creates_in_progress_attempt(
        self, in_progress_attempt: AuthenticationAttempt
    ):
        assert in_progress_attempt.status == AttemptStatus.IN_PROGRESS

    def test_stores_required_factors(
        self,
        in_progress_attempt: AuthenticationAttempt,
        mfa_factors: RequiredFactors,
    ):
        assert in_progress_attempt.required_factors == mfa_factors

    def test_initializes_empty_verified_factors(
        self, in_progress_attempt: AuthenticationAttempt
    ):
        assert in_progress_attempt.verified_factors.factors == ()

    def test_has_no_verification_code(self, in_progress_attempt: AuthenticationAttempt):
        assert in_progress_attempt.verification_code is None


# --- Set verification code ---


class TestSetVerificationCode:
    def test_assigns_code(
        self,
        in_progress_attempt: AuthenticationAttempt,
        verification_code: VerificationCode,
        now: datetime,
    ):
        in_progress_attempt.set_verification_code(verification_code, now)
        assert in_progress_attempt.verification_code == verification_code

    def test_records_verification_code_generated_event(
        self,
        in_progress_attempt: AuthenticationAttempt,
        verification_code: VerificationCode,
        now: datetime,
    ):
        in_progress_attempt.set_verification_code(verification_code, now)
        events = [
            e
            for e in in_progress_attempt.events
            if isinstance(e, VerificationCodeGenerated)
        ]
        assert len(events) == 1

    def test_raises_when_not_in_progress(
        self,
        in_progress_attempt: AuthenticationAttempt,
        verification_code: VerificationCode,
        now: datetime,
    ):
        in_progress_attempt.fail(now)
        with pytest.raises(AttemptNotInProgressError):
            in_progress_attempt.set_verification_code(verification_code, now)

    def test_raises_when_expired(
        self,
        attempt_id: AuthAttemptId,
        account_id: AccountId,
        mfa_factors: RequiredFactors,
        past: datetime,
        verification_code: VerificationCode,
        now: datetime,
    ):
        expired_attempt = AuthenticationAttempt.initiate(
            attempt_id, account_id, mfa_factors, past
        )
        with pytest.raises(AttemptExpiredError):
            expired_attempt.set_verification_code(verification_code, now)

    def test_raises_when_possession_not_required(
        self,
        knowledge_only_attempt: AuthenticationAttempt,
        verification_code: VerificationCode,
        now: datetime,
    ):
        with pytest.raises(FactorNotRequiredError):
            knowledge_only_attempt.set_verification_code(verification_code, now)

    def test_raises_when_active_code_exists(
        self,
        in_progress_attempt: AuthenticationAttempt,
        verification_code: VerificationCode,
        now: datetime,
    ):
        in_progress_attempt.set_verification_code(verification_code, now)
        another_code = VerificationCode(
            hashed_value=HashedVerificationCode(value="$other"),
            expires_at=now + timedelta(hours=1),
        )
        with pytest.raises(VerificationCodeAlreadyGeneratedError):
            in_progress_attempt.set_verification_code(another_code, now)


# --- Verify factor ---


class TestVerifyFactor:
    def test_adds_to_verified(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.verify_factor(AuthenticationFactor.KNOWLEDGE, now)
        assert in_progress_attempt.verified_factors.has_factor(
            AuthenticationFactor.KNOWLEDGE
        )

    def test_completes_when_all_satisfied(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.verify_factor(AuthenticationFactor.KNOWLEDGE, now)
        in_progress_attempt.verify_factor(AuthenticationFactor.POSSESSION, now)
        assert in_progress_attempt.status == AttemptStatus.SUCCEEDED

    def test_records_authentication_succeeded_on_completion(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.verify_factor(AuthenticationFactor.KNOWLEDGE, now)
        in_progress_attempt.verify_factor(AuthenticationFactor.POSSESSION, now)
        succeeded_events = [
            e
            for e in in_progress_attempt.events
            if isinstance(e, AuthenticationSucceeded)
        ]
        assert len(succeeded_events) == 1

    def test_does_not_complete_when_partial(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.verify_factor(AuthenticationFactor.KNOWLEDGE, now)
        assert in_progress_attempt.status == AttemptStatus.IN_PROGRESS

    def test_raises_when_not_in_progress(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.fail(now)
        with pytest.raises(AttemptNotInProgressError):
            in_progress_attempt.verify_factor(AuthenticationFactor.KNOWLEDGE, now)

    def test_raises_when_expired(
        self,
        attempt_id: AuthAttemptId,
        account_id: AccountId,
        mfa_factors: RequiredFactors,
        past: datetime,
        now: datetime,
    ):
        expired_attempt = AuthenticationAttempt.initiate(
            attempt_id, account_id, mfa_factors, past
        )
        with pytest.raises(AttemptExpiredError):
            expired_attempt.verify_factor(AuthenticationFactor.KNOWLEDGE, now)

    def test_raises_when_factor_not_required(
        self,
        knowledge_only_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        with pytest.raises(FactorNotRequiredError):
            knowledge_only_attempt.verify_factor(AuthenticationFactor.POSSESSION, now)

    def test_raises_when_factor_already_verified(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.verify_factor(AuthenticationFactor.KNOWLEDGE, now)
        with pytest.raises(FactorAlreadyVerifiedError):
            in_progress_attempt.verify_factor(AuthenticationFactor.KNOWLEDGE, now)


# --- Fail ---


class TestAuthenticationAttemptFail:
    def test_transitions_to_failed(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.fail(now)
        assert in_progress_attempt.status == AttemptStatus.FAILED

    def test_records_authentication_failed_event(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.fail(now)
        failed_events = [
            e for e in in_progress_attempt.events if isinstance(e, AuthenticationFailed)
        ]
        assert len(failed_events) == 1

    def test_raises_when_not_in_progress(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.fail(now)
        with pytest.raises(AttemptNotInProgressError):
            in_progress_attempt.fail(now)

    def test_raises_when_expired(
        self,
        attempt_id: AuthAttemptId,
        account_id: AccountId,
        mfa_factors: RequiredFactors,
        past: datetime,
        now: datetime,
    ):
        expired_attempt = AuthenticationAttempt.initiate(
            attempt_id, account_id, mfa_factors, past
        )
        with pytest.raises(AttemptExpiredError):
            expired_attempt.fail(now)


# --- Expire ---


class TestAuthenticationAttemptExpire:
    def test_transitions_to_expired(
        self,
        attempt_id: AuthAttemptId,
        account_id: AccountId,
        mfa_factors: RequiredFactors,
        past: datetime,
        now: datetime,
    ):
        attempt = AuthenticationAttempt.initiate(
            attempt_id, account_id, mfa_factors, past
        )
        attempt.expire(now)
        assert attempt.status == AttemptStatus.EXPIRED

    def test_raises_when_not_in_progress(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        in_progress_attempt.fail(now)
        with pytest.raises(AttemptNotInProgressError):
            in_progress_attempt.expire(now)

    def test_raises_when_not_actually_expired(
        self,
        in_progress_attempt: AuthenticationAttempt,
        now: datetime,
    ):
        with pytest.raises(AttemptNotExpiredError):
            in_progress_attempt.expire(now)
