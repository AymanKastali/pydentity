from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from pydentity.authentication.domain.verification_request.value_objects import (
    HashedVerificationRequestToken,
    RawVerificationRequestToken,
    VerificationFailureReason,
    VerificationPolicy,
    VerificationRequestExpiry,
    VerificationRequestId,
    VerificationRequestStatus,
    VerificationRequestType,
)
from pydentity.shared_kernel.building_blocks import ValueObject


class TestVerificationRequestStatus:
    def test_has_pending(self):
        assert VerificationRequestStatus.PENDING == "pending"

    def test_has_verified(self):
        assert VerificationRequestStatus.VERIFIED == "verified"

    def test_has_invalidated(self):
        assert VerificationRequestStatus.INVALIDATED == "invalidated"

    def test_has_expired(self):
        assert VerificationRequestStatus.EXPIRED == "expired"


class TestVerificationRequestType:
    def test_has_email_verification(self):
        assert VerificationRequestType.EMAIL_VERIFICATION == "email_verification"

    def test_has_password_reset(self):
        assert VerificationRequestType.PASSWORD_RESET == "password_reset"


class TestVerificationFailureReason:
    def test_has_invalid_token(self):
        assert VerificationFailureReason.INVALID_TOKEN == "invalid_token"

    def test_has_expired(self):
        assert VerificationFailureReason.EXPIRED == "expired"

    def test_has_already_verified(self):
        assert VerificationFailureReason.ALREADY_VERIFIED == "already_verified"


class TestVerificationRequestId:
    def test_stores_uuid(self):
        uid = uuid4()
        rid = VerificationRequestId(value=uid)
        assert rid.value == uid

    def test_frozen(self):
        rid = VerificationRequestId(value=uuid4())
        with pytest.raises(FrozenInstanceError):
            rid.value = uuid4()  # type: ignore[misc]

    def test_equal_by_value(self):
        uid = uuid4()
        assert VerificationRequestId(value=uid) == VerificationRequestId(value=uid)

    def test_hashable(self):
        uid = uuid4()
        a = VerificationRequestId(value=uid)
        b = VerificationRequestId(value=uid)
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_is_value_object(self):
        rid = VerificationRequestId(value=uuid4())
        assert isinstance(rid, ValueObject)


class TestRawVerificationRequestToken:
    def test_valid_creation(self):
        token = RawVerificationRequestToken(value="abc123")
        assert token.value == "abc123"

    def test_frozen(self):
        token = RawVerificationRequestToken(value="abc123")
        with pytest.raises(FrozenInstanceError):
            token.value = "other"  # type: ignore[misc]

    def test_equal_by_value(self):
        assert RawVerificationRequestToken(
            value="abc"
        ) == RawVerificationRequestToken(value="abc")

    def test_hashable(self):
        a = RawVerificationRequestToken(value="abc")
        b = RawVerificationRequestToken(value="abc")
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_is_value_object(self):
        token = RawVerificationRequestToken(value="abc")
        assert isinstance(token, ValueObject)

    def test_blank_raises(self):
        with pytest.raises(ValueError):
            RawVerificationRequestToken(value="   ")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            RawVerificationRequestToken(value="")


class TestHashedVerificationRequestToken:
    def test_valid_creation(self):
        token = HashedVerificationRequestToken(value="hashed123")
        assert token.value == "hashed123"

    def test_frozen(self):
        token = HashedVerificationRequestToken(value="hashed123")
        with pytest.raises(FrozenInstanceError):
            token.value = "other"  # type: ignore[misc]

    def test_equal_by_value(self):
        assert HashedVerificationRequestToken(
            value="h"
        ) == HashedVerificationRequestToken(value="h")

    def test_hashable(self):
        a = HashedVerificationRequestToken(value="h")
        b = HashedVerificationRequestToken(value="h")
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_is_value_object(self):
        token = HashedVerificationRequestToken(value="h")
        assert isinstance(token, ValueObject)

    def test_blank_raises(self):
        with pytest.raises(ValueError):
            HashedVerificationRequestToken(value="   ")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            HashedVerificationRequestToken(value="")


class TestVerificationPolicy:
    def test_valid_creation(self):
        policy = VerificationPolicy(
            email_verification_ttl_seconds=3600,
            password_reset_ttl_seconds=900,
        )
        assert policy.email_verification_ttl_seconds == 3600
        assert policy.password_reset_ttl_seconds == 900

    def test_frozen(self):
        policy = VerificationPolicy(
            email_verification_ttl_seconds=3600,
            password_reset_ttl_seconds=900,
        )
        with pytest.raises(FrozenInstanceError):
            policy.email_verification_ttl_seconds = 1  # type: ignore[misc]

    def test_equal_by_value(self):
        assert VerificationPolicy(
            email_verification_ttl_seconds=3600,
            password_reset_ttl_seconds=900,
        ) == VerificationPolicy(
            email_verification_ttl_seconds=3600,
            password_reset_ttl_seconds=900,
        )

    def test_is_value_object(self):
        policy = VerificationPolicy(
            email_verification_ttl_seconds=3600,
            password_reset_ttl_seconds=900,
        )
        assert isinstance(policy, ValueObject)

    def test_zero_email_ttl_raises(self):
        with pytest.raises(ValueError):
            VerificationPolicy(
                email_verification_ttl_seconds=0,
                password_reset_ttl_seconds=900,
            )

    def test_negative_email_ttl_raises(self):
        with pytest.raises(ValueError):
            VerificationPolicy(
                email_verification_ttl_seconds=-1,
                password_reset_ttl_seconds=900,
            )

    def test_zero_password_reset_ttl_raises(self):
        with pytest.raises(ValueError):
            VerificationPolicy(
                email_verification_ttl_seconds=3600,
                password_reset_ttl_seconds=0,
            )

    def test_negative_password_reset_ttl_raises(self):
        with pytest.raises(ValueError):
            VerificationPolicy(
                email_verification_ttl_seconds=3600,
                password_reset_ttl_seconds=-1,
            )


class TestVerificationRequestExpiry:
    def test_valid_creation(self):
        now = datetime.now(timezone.utc)
        expiry = VerificationRequestExpiry(value=now)
        assert expiry.value == now

    def test_frozen(self):
        expiry = VerificationRequestExpiry(value=datetime.now(timezone.utc))
        with pytest.raises(FrozenInstanceError):
            expiry.value = datetime.now(timezone.utc)  # type: ignore[misc]

    def test_equal_by_value(self):
        now = datetime.now(timezone.utc)
        assert VerificationRequestExpiry(value=now) == VerificationRequestExpiry(
            value=now
        )

    def test_is_value_object(self):
        expiry = VerificationRequestExpiry(value=datetime.now(timezone.utc))
        assert isinstance(expiry, ValueObject)
