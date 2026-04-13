from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from pydentity.authentication.domain.verification_request.aggregate import (
    VerificationRequest,
)
from unittest.mock import AsyncMock

from pydentity.authentication.domain.verification_request.errors import (
    InvalidVerificationTokenError,
    VerificationRequestExpiredError,
)
from pydentity.authentication.domain.verification_request.events import (
    VerificationRequestExpired,
    VerificationRequestInvalidated,
    VerificationRequestVerified,
)
from pydentity.authentication.domain.verification_request.interfaces import (
    VerificationRequestTokenHasher,
    VerificationRequestTokenVerifier,
)
from pydentity.authentication.domain.verification_request.repository import (
    VerificationRequestRepository,
)
from pydentity.authentication.domain.verification_request.services import (
    IssueEmailVerificationRequest,
    IssuePasswordResetRequest,
    VerifyVerificationRequestToken,
)
from pydentity.authentication.domain.verification_request.value_objects import (
    HashedVerificationRequestToken,
    RawVerificationRequestToken,
    VerificationPolicy,
    VerificationRequestExpiry,
    VerificationRequestId,
    VerificationRequestStatus,
    VerificationRequestType,
)
from pydentity.shared_kernel.value_objects import AccountId


class _StubTokenHasher(VerificationRequestTokenHasher):
    def hash(
        self, token: RawVerificationRequestToken
    ) -> HashedVerificationRequestToken:
        return HashedVerificationRequestToken(value=f"hashed-{token.value}")


class _StubTokenVerifier(VerificationRequestTokenVerifier):
    def __init__(self, *, result: bool) -> None:
        self._result = result

    def verify(
        self,
        token: RawVerificationRequestToken,
        hashed: HashedVerificationRequestToken,
    ) -> bool:
        return self._result


def _make_pending_request(
    expiry: VerificationRequestExpiry | None = None,
) -> VerificationRequest:
    return VerificationRequest.create(
        verification_request_id=VerificationRequestId(value=uuid4()),
        account_id=AccountId(value=uuid4()),
        request_type=VerificationRequestType.EMAIL_VERIFICATION,
        hashed_token=HashedVerificationRequestToken(value="hashed-token"),
        expiry=expiry
        or VerificationRequestExpiry(
            value=datetime.now(timezone.utc) + timedelta(hours=1),
        ),
    )


class TestVerifyVerificationRequestToken:
    def test_valid_token_transitions_to_verified(self):
        request = _make_pending_request()
        service = VerifyVerificationRequestToken(
            verifier=_StubTokenVerifier(result=True),
        )
        service.verify(
            request=request,
            token=RawVerificationRequestToken(value="raw-token"),
            current_time=datetime.now(timezone.utc),
        )
        assert request.status == VerificationRequestStatus.VERIFIED

    def test_valid_token_records_verified_event(self):
        request = _make_pending_request()
        request.clear_events()
        service = VerifyVerificationRequestToken(
            verifier=_StubTokenVerifier(result=True),
        )
        service.verify(
            request=request,
            token=RawVerificationRequestToken(value="raw-token"),
            current_time=datetime.now(timezone.utc),
        )
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], VerificationRequestVerified)

    def test_invalid_token_raises(self):
        request = _make_pending_request()
        service = VerifyVerificationRequestToken(
            verifier=_StubTokenVerifier(result=False),
        )
        with pytest.raises(InvalidVerificationTokenError):
            service.verify(
                request=request,
                token=RawVerificationRequestToken(value="wrong-token"),
                current_time=datetime.now(timezone.utc),
            )

    def test_invalid_token_does_not_change_status(self):
        request = _make_pending_request()
        service = VerifyVerificationRequestToken(
            verifier=_StubTokenVerifier(result=False),
        )
        with pytest.raises(InvalidVerificationTokenError):
            service.verify(
                request=request,
                token=RawVerificationRequestToken(value="wrong-token"),
                current_time=datetime.now(timezone.utc),
            )
        assert request.status == VerificationRequestStatus.PENDING

    def test_expired_request_raises(self):
        past_expiry = VerificationRequestExpiry(
            value=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        request = _make_pending_request(expiry=past_expiry)
        service = VerifyVerificationRequestToken(
            verifier=_StubTokenVerifier(result=True),
        )
        with pytest.raises(VerificationRequestExpiredError):
            service.verify(
                request=request,
                token=RawVerificationRequestToken(value="raw-token"),
                current_time=datetime.now(timezone.utc),
            )

    def test_expired_request_transitions_to_expired(self):
        past_expiry = VerificationRequestExpiry(
            value=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        request = _make_pending_request(expiry=past_expiry)
        service = VerifyVerificationRequestToken(
            verifier=_StubTokenVerifier(result=True),
        )
        with pytest.raises(VerificationRequestExpiredError):
            service.verify(
                request=request,
                token=RawVerificationRequestToken(value="raw-token"),
                current_time=datetime.now(timezone.utc),
            )
        assert request.status == VerificationRequestStatus.EXPIRED

    def test_expired_request_records_expired_event(self):
        past_expiry = VerificationRequestExpiry(
            value=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        request = _make_pending_request(expiry=past_expiry)
        request.clear_events()
        service = VerifyVerificationRequestToken(
            verifier=_StubTokenVerifier(result=True),
        )
        with pytest.raises(VerificationRequestExpiredError):
            service.verify(
                request=request,
                token=RawVerificationRequestToken(value="raw-token"),
                current_time=datetime.now(timezone.utc),
            )
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], VerificationRequestExpired)


_POLICY = VerificationPolicy(
    email_verification_ttl_seconds=3600,
    password_reset_ttl_seconds=900,
)


def _make_email_verification_service(
    existing_request: VerificationRequest | None = None,
) -> IssueEmailVerificationRequest:
    repo = AsyncMock(spec=VerificationRequestRepository)
    repo.find_pending_by_account_id_and_type.return_value = existing_request
    return IssueEmailVerificationRequest(hasher=_StubTokenHasher(), repository=repo)


def _make_password_reset_service(
    existing_request: VerificationRequest | None = None,
) -> IssuePasswordResetRequest:
    repo = AsyncMock(spec=VerificationRequestRepository)
    repo.find_pending_by_account_id_and_type.return_value = existing_request
    return IssuePasswordResetRequest(hasher=_StubTokenHasher(), repository=repo)


class TestIssueEmailVerificationRequest:
    @pytest.mark.asyncio
    async def test_creates_pending_request(self):
        service = _make_email_verification_service()
        request, _ = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert request.status == VerificationRequestStatus.PENDING

    @pytest.mark.asyncio
    async def test_returns_email_verification_type(self):
        service = _make_email_verification_service()
        request, _ = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert request.request_type == VerificationRequestType.EMAIL_VERIFICATION

    @pytest.mark.asyncio
    async def test_returns_raw_token(self):
        service = _make_email_verification_service()
        raw = RawVerificationRequestToken(value="my-token")
        _, returned_token = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=raw,
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert returned_token == raw

    @pytest.mark.asyncio
    async def test_hashes_token(self):
        service = _make_email_verification_service()
        request, _ = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="my-token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert request.hashed_token.value == "hashed-my-token"

    @pytest.mark.asyncio
    async def test_expiry_uses_email_ttl(self):
        now = datetime.now(timezone.utc)
        service = _make_email_verification_service()
        request, _ = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=now,
        )
        assert request.expiry.value > now

    @pytest.mark.asyncio
    async def test_invalidates_existing_pending_request(self):
        existing = _make_pending_request()
        service = _make_email_verification_service(existing_request=existing)
        await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert existing.status == VerificationRequestStatus.INVALIDATED

    @pytest.mark.asyncio
    async def test_invalidated_request_records_event(self):
        existing = _make_pending_request()
        existing.clear_events()
        service = _make_email_verification_service(existing_request=existing)
        await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert len(existing.events) == 1
        assert isinstance(existing.events[0], VerificationRequestInvalidated)

    @pytest.mark.asyncio
    async def test_no_existing_request_creates_normally(self):
        service = _make_email_verification_service(existing_request=None)
        request, _ = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert request.status == VerificationRequestStatus.PENDING


class TestIssuePasswordResetRequest:
    @pytest.mark.asyncio
    async def test_creates_pending_request(self):
        service = _make_password_reset_service()
        request, _ = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert request.status == VerificationRequestStatus.PENDING

    @pytest.mark.asyncio
    async def test_returns_password_reset_type(self):
        service = _make_password_reset_service()
        request, _ = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert request.request_type == VerificationRequestType.PASSWORD_RESET

    @pytest.mark.asyncio
    async def test_invalidates_existing_pending_request(self):
        existing = _make_pending_request()
        service = _make_password_reset_service(existing_request=existing)
        await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=datetime.now(timezone.utc),
        )
        assert existing.status == VerificationRequestStatus.INVALIDATED

    @pytest.mark.asyncio
    async def test_expiry_uses_password_reset_ttl(self):
        now = datetime.now(timezone.utc)
        service = _make_password_reset_service()
        request, _ = await service.issue(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            raw_token=RawVerificationRequestToken(value="token"),
            policy=_POLICY,
            current_time=now,
        )
        assert request.expiry.value > now
