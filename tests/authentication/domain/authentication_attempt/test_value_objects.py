from datetime import UTC, datetime, timedelta

import pytest

from pydentity.authentication.domain.authentication_attempt.errors import (
    AttemptNotInProgressError,
    FactorAlreadyVerifiedError,
    FactorNotRequiredError,
)
from pydentity.authentication.domain.authentication_attempt.value_objects import (
    AttemptStatus,
    AuthenticationFactor,
    HashedVerificationCode,
    RequiredFactors,
    VerificationCode,
    VerifiedFactors,
)

# --- AttemptStatus ---


class TestAttemptStatus:
    def test_in_progress_query(self):
        assert AttemptStatus.IN_PROGRESS.is_in_progress is True

    def test_succeeded_query(self):
        assert AttemptStatus.SUCCEEDED.is_succeeded is True
        assert AttemptStatus.SUCCEEDED.is_in_progress is False

    def test_failed_query(self):
        assert AttemptStatus.FAILED.is_failed is True

    def test_expired_query(self):
        assert AttemptStatus.EXPIRED.is_expired is True

    def test_guard_is_in_progress_passes(self):
        AttemptStatus.IN_PROGRESS.guard_is_in_progress()

    def test_guard_is_in_progress_raises_when_succeeded(self):
        with pytest.raises(AttemptNotInProgressError):
            AttemptStatus.SUCCEEDED.guard_is_in_progress()

    def test_guard_is_in_progress_raises_when_failed(self):
        with pytest.raises(AttemptNotInProgressError):
            AttemptStatus.FAILED.guard_is_in_progress()


# --- AuthenticationFactor ---


class TestAuthenticationFactor:
    def test_values(self):
        assert AuthenticationFactor.KNOWLEDGE == "knowledge"
        assert AuthenticationFactor.POSSESSION == "possession"
        assert AuthenticationFactor.INHERENCE == "inherence"


# --- RequiredFactors ---


class TestRequiredFactors:
    def test_valid_creation(self):
        factors = RequiredFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        assert AuthenticationFactor.KNOWLEDGE in factors.factors

    def test_has_factor_true(self):
        factors = RequiredFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        assert factors.has_factor(AuthenticationFactor.KNOWLEDGE) is True

    def test_has_factor_false(self):
        factors = RequiredFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        assert factors.has_factor(AuthenticationFactor.POSSESSION) is False

    def test_is_satisfied_by_matching(self):
        required = RequiredFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        verified = VerifiedFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        assert required.is_satisfied_by(verified) is True

    def test_is_not_satisfied_by_partial(self):
        required = RequiredFactors(
            factors=(AuthenticationFactor.KNOWLEDGE, AuthenticationFactor.POSSESSION)
        )
        verified = VerifiedFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        assert required.is_satisfied_by(verified) is False

    def test_guard_has_factor_passes(self):
        factors = RequiredFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        factors.guard_has_factor(AuthenticationFactor.KNOWLEDGE)

    def test_guard_has_factor_raises(self):
        factors = RequiredFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        with pytest.raises(FactorNotRequiredError):
            factors.guard_has_factor(AuthenticationFactor.POSSESSION)

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            RequiredFactors(factors=())

    def test_rejects_duplicates(self):
        with pytest.raises(ValueError):
            RequiredFactors(
                factors=(
                    AuthenticationFactor.KNOWLEDGE,
                    AuthenticationFactor.KNOWLEDGE,
                )
            )

    def test_rejects_exceeding_max_size(self):
        with pytest.raises(ValueError):
            RequiredFactors(
                factors=(
                    AuthenticationFactor.KNOWLEDGE,
                    AuthenticationFactor.POSSESSION,
                    AuthenticationFactor.INHERENCE,
                    AuthenticationFactor.KNOWLEDGE,
                )
            )


# --- VerifiedFactors ---


class TestVerifiedFactors:
    def test_initialize_empty(self):
        verified = VerifiedFactors.initialize()
        assert verified.factors == ()

    def test_with_factor_adds(self):
        verified = VerifiedFactors.initialize()
        updated = verified.with_factor(AuthenticationFactor.KNOWLEDGE)
        assert AuthenticationFactor.KNOWLEDGE in updated.factors

    def test_has_factor(self):
        verified = VerifiedFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        assert verified.has_factor(AuthenticationFactor.KNOWLEDGE) is True

    def test_guard_factor_not_verified_passes(self):
        verified = VerifiedFactors.initialize()
        verified.guard_factor_not_verified(AuthenticationFactor.KNOWLEDGE)

    def test_guard_factor_not_verified_raises(self):
        verified = VerifiedFactors(factors=(AuthenticationFactor.KNOWLEDGE,))
        with pytest.raises(FactorAlreadyVerifiedError):
            verified.guard_factor_not_verified(AuthenticationFactor.KNOWLEDGE)


# --- HashedVerificationCode ---


class TestHashedVerificationCode:
    def test_valid_creation(self):
        code = HashedVerificationCode(value="$hashed")
        assert code.value == "$hashed"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            HashedVerificationCode(value="")

    def test_rejects_exceeding_max_length(self):
        with pytest.raises(ValueError):
            HashedVerificationCode(value="x" * 257)


# --- VerificationCode ---


class TestVerificationCode:
    def test_is_active_before_expiry(self):
        expires_at = datetime(2026, 6, 1, tzinfo=UTC)
        code = VerificationCode(
            hashed_value=HashedVerificationCode(value="$h"),
            expires_at=expires_at,
        )
        before = expires_at - timedelta(minutes=1)
        assert code.is_active(before) is True

    def test_is_expired_after_expiry(self):
        expires_at = datetime(2026, 1, 1, tzinfo=UTC)
        code = VerificationCode(
            hashed_value=HashedVerificationCode(value="$h"),
            expires_at=expires_at,
        )
        after = expires_at + timedelta(minutes=1)
        assert code.is_expired(after) is True
        assert code.is_active(after) is False
