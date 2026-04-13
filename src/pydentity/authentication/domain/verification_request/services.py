from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import override

from pydentity.authentication.domain.verification_request.aggregate import (
    VerificationRequest,
)
from pydentity.authentication.domain.verification_request.errors import (
    InvalidVerificationTokenError,
    VerificationRequestExpiredError,
)
from pydentity.authentication.domain.verification_request.interfaces import (
    VerificationRequestTokenHasher,
    VerificationRequestTokenVerifier,
)
from pydentity.authentication.domain.verification_request.repository import (
    VerificationRequestRepository,
)
from pydentity.authentication.domain.verification_request.value_objects import (
    RawVerificationRequestToken,
    VerificationPolicy,
    VerificationRequestExpiry,
    VerificationRequestId,
    VerificationRequestType,
)
from pydentity.shared_kernel.value_objects import AccountId


class _IssueVerificationRequest(ABC):
    def __init__(
        self,
        hasher: VerificationRequestTokenHasher,
        repository: VerificationRequestRepository,
    ) -> None:
        self._hasher = hasher
        self._repository = repository

    async def issue(
        self,
        verification_request_id: VerificationRequestId,
        account_id: AccountId,
        raw_token: RawVerificationRequestToken,
        policy: VerificationPolicy,
        current_time: datetime,
    ) -> tuple[VerificationRequest, RawVerificationRequestToken]:
        await self._invalidate_pending(account_id)
        return self._create_request(
            verification_request_id,
            account_id,
            raw_token,
            self._ttl_seconds(policy),
            current_time,
        )

    async def _invalidate_pending(self, account_id: AccountId) -> None:
        existing = await self._repository.find_pending_by_account_id_and_type(
            account_id, self._request_type()
        )
        if existing is not None:
            existing.invalidate()

    def _create_request(
        self,
        verification_request_id: VerificationRequestId,
        account_id: AccountId,
        raw_token: RawVerificationRequestToken,
        ttl_seconds: int,
        current_time: datetime,
    ) -> tuple[VerificationRequest, RawVerificationRequestToken]:
        hashed_token = self._hasher.hash(raw_token)
        expiry = VerificationRequestExpiry(
            value=current_time + timedelta(seconds=ttl_seconds)
        )
        request = VerificationRequest.create(
            verification_request_id=verification_request_id,
            account_id=account_id,
            request_type=self._request_type(),
            hashed_token=hashed_token,
            expiry=expiry,
        )
        return request, raw_token

    @abstractmethod
    def _request_type(self) -> VerificationRequestType: ...

    @abstractmethod
    def _ttl_seconds(self, policy: VerificationPolicy) -> int: ...


class IssueEmailVerificationRequest(_IssueVerificationRequest):
    @override
    def _request_type(self) -> VerificationRequestType:
        return VerificationRequestType.EMAIL_VERIFICATION

    @override
    def _ttl_seconds(self, policy: VerificationPolicy) -> int:
        return policy.email_verification_ttl_seconds


class IssuePasswordResetRequest(_IssueVerificationRequest):
    @override
    def _request_type(self) -> VerificationRequestType:
        return VerificationRequestType.PASSWORD_RESET

    @override
    def _ttl_seconds(self, policy: VerificationPolicy) -> int:
        return policy.password_reset_ttl_seconds


class VerifyVerificationRequestToken:
    def __init__(self, verifier: VerificationRequestTokenVerifier) -> None:
        self._verifier = verifier

    def verify(
        self,
        request: VerificationRequest,
        token: RawVerificationRequestToken,
        current_time: datetime,
    ) -> None:
        self._guard_request_not_expired(request, current_time)
        self._guard_token_matches(request, token)
        request.verify()

    def _guard_request_not_expired(
        self, request: VerificationRequest, current_time: datetime
    ) -> None:
        if request.is_expired_at(current_time):
            request.expire()
            raise VerificationRequestExpiredError()

    def _guard_token_matches(
        self, request: VerificationRequest, token: RawVerificationRequestToken
    ) -> None:
        if not self._verifier.verify(token, request.hashed_token):
            raise InvalidVerificationTokenError()
