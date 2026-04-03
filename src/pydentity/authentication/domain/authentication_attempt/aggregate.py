from typing import TYPE_CHECKING

from pydentity.authentication.domain.authentication_attempt.aggregate_id import (
    AuthAttemptId,
)
from pydentity.authentication.domain.authentication_attempt.errors import (
    AttemptExpiredError,
    AttemptNotExpiredError,
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
    RequiredFactors,
    VerificationCode,
    VerifiedFactors,
)
from pydentity.shared_kernel import AggregateRoot

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.shared_kernel import AccountId


class AuthenticationAttempt(AggregateRoot[AuthAttemptId]):
    def __init__(
        self,
        attempt_id: AuthAttemptId,
        account_id: AccountId,
        status: AttemptStatus,
        required_factors: RequiredFactors,
        verified_factors: VerifiedFactors,
        expires_at: datetime,
        verification_code: VerificationCode | None,
    ) -> None:
        super().__init__(attempt_id)
        self._account_id: AccountId = account_id
        self._status: AttemptStatus = status
        self._required_factors: RequiredFactors = required_factors
        self._verified_factors: VerifiedFactors = verified_factors
        self._expires_at: datetime = expires_at
        self._verification_code: VerificationCode | None = verification_code

    # --- Creation ---

    @classmethod
    def initiate(
        cls,
        attempt_id: AuthAttemptId,
        account_id: AccountId,
        required_factors: RequiredFactors,
        expires_at: datetime,
    ) -> AuthenticationAttempt:
        return cls(
            attempt_id=attempt_id,
            account_id=account_id,
            status=AttemptStatus.IN_PROGRESS,
            required_factors=required_factors,
            verified_factors=VerifiedFactors.initialize(),
            expires_at=expires_at,
            verification_code=None,
        )

    # --- Queries ---

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def status(self) -> AttemptStatus:
        return self._status

    @property
    def required_factors(self) -> RequiredFactors:
        return self._required_factors

    @property
    def verified_factors(self) -> VerifiedFactors:
        return self._verified_factors

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def verification_code(self) -> VerificationCode | None:
        return self._verification_code

    def is_expired(self, now: datetime) -> bool:
        return now >= self._expires_at

    # --- Verification code ---

    def set_verification_code(
        self, verification_code: VerificationCode, now: datetime
    ) -> None:
        self._status.guard_is_in_progress()
        self._guard_not_expired(now)
        self._required_factors.guard_has_factor(AuthenticationFactor.POSSESSION)
        self._guard_no_active_verification_code(now)
        self._assign_verification_code(verification_code)
        self.record_event(
            VerificationCodeGenerated(
                occurred_at=now, attempt_id=self._id, account_id=self._account_id
            )
        )

    def _guard_not_expired(self, now: datetime) -> None:
        if self.is_expired(now):
            raise AttemptExpiredError()

    def _guard_no_active_verification_code(self, now: datetime) -> None:
        if self._verification_code is not None and self._verification_code.is_active(
            now
        ):
            raise VerificationCodeAlreadyGeneratedError()

    def _assign_verification_code(self, verification_code: VerificationCode) -> None:
        self._verification_code = verification_code

    # --- Factor verification ---

    def verify_factor(self, factor: AuthenticationFactor, now: datetime) -> None:
        self._status.guard_is_in_progress()
        self._guard_not_expired(now)
        self._required_factors.guard_has_factor(factor)
        self._verified_factors.guard_factor_not_verified(factor)
        self._record_verified_factor(factor)
        self._complete_if_all_factors_verified(now)

    def _record_verified_factor(self, factor: AuthenticationFactor) -> None:
        self._verified_factors = self._verified_factors.with_factor(factor)

    def _complete_if_all_factors_verified(self, now: datetime) -> None:
        if not self._required_factors.is_satisfied_by(self._verified_factors):
            return
        self._mark_succeeded()
        self.record_event(
            AuthenticationSucceeded(
                occurred_at=now,
                attempt_id=self._id,
                account_id=self._account_id,
                factors_used=self._verified_factors.factors,
            )
        )

    def _mark_succeeded(self) -> None:
        self._status = AttemptStatus.SUCCEEDED

    # --- Failure ---

    def fail(self, now: datetime) -> None:
        self._status.guard_is_in_progress()
        self._guard_not_expired(now)
        self._mark_failed()
        self.record_event(
            AuthenticationFailed(
                occurred_at=now,
                attempt_id=self._id,
                account_id=self._account_id,
            )
        )

    def _mark_failed(self) -> None:
        self._status = AttemptStatus.FAILED

    # --- Expiration ---

    def expire(self, now: datetime) -> None:
        self._status.guard_is_in_progress()
        self._guard_is_expired(now)
        self._mark_expired()

    def _guard_is_expired(self, now: datetime) -> None:
        if not self.is_expired(now):
            raise AttemptNotExpiredError()

    def _mark_expired(self) -> None:
        self._status = AttemptStatus.EXPIRED
