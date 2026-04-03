import pytest

from pydentity.authentication.domain.trusted_device.errors import (
    DeviceAlreadyExpiredError,
    DeviceAlreadyRevokedError,
    DeviceLimitExceededError,
)
from pydentity.authentication.domain.trusted_device.value_objects import (
    DeviceFingerprint,
    DevicePolicy,
    DeviceRevocationReason,
    TrustedDeviceStatus,
)

# --- DeviceFingerprint ---


class TestDeviceFingerprint:
    def test_valid_creation(self):
        fp = DeviceFingerprint(value="browser-sha256-abc123")
        assert fp.value == "browser-sha256-abc123"

    def test_rejects_blank(self):
        with pytest.raises(ValueError):
            DeviceFingerprint(value="   ")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            DeviceFingerprint(value="")

    def test_rejects_exceeding_max_length(self):
        with pytest.raises(ValueError):
            DeviceFingerprint(value="x" * 257)


# --- TrustedDeviceStatus ---


class TestTrustedDeviceStatus:
    def test_registered_query(self):
        assert TrustedDeviceStatus.REGISTERED.is_registered is True

    def test_revoked_query(self):
        assert TrustedDeviceStatus.REVOKED.is_revoked is True

    def test_expired_query(self):
        assert TrustedDeviceStatus.EXPIRED.is_expired is True

    def test_guard_not_revoked_passes(self):
        TrustedDeviceStatus.REGISTERED.guard_not_revoked()

    def test_guard_not_revoked_raises(self):
        with pytest.raises(DeviceAlreadyRevokedError):
            TrustedDeviceStatus.REVOKED.guard_not_revoked()

    def test_guard_not_expired_passes(self):
        TrustedDeviceStatus.REGISTERED.guard_not_expired()

    def test_guard_not_expired_raises(self):
        with pytest.raises(DeviceAlreadyExpiredError):
            TrustedDeviceStatus.EXPIRED.guard_not_expired()


# --- DevicePolicy ---


class TestDevicePolicy:
    def test_valid_creation(self):
        policy = DevicePolicy(max_devices=5)
        assert policy.max_devices == 5

    def test_rejects_zero(self):
        with pytest.raises(ValueError):
            DevicePolicy(max_devices=0)

    def test_is_limit_exceeded_at_boundary(self):
        policy = DevicePolicy(max_devices=5)
        assert policy.is_limit_exceeded(5) is True

    def test_is_limit_not_exceeded_below(self):
        policy = DevicePolicy(max_devices=5)
        assert policy.is_limit_exceeded(4) is False

    def test_guard_limit_not_exceeded_passes(self):
        policy = DevicePolicy(max_devices=5)
        policy.guard_limit_not_exceeded(4)

    def test_guard_limit_not_exceeded_raises(self):
        policy = DevicePolicy(max_devices=5)
        with pytest.raises(DeviceLimitExceededError):
            policy.guard_limit_not_exceeded(5)


# --- DeviceRevocationReason ---


class TestDeviceRevocationReason:
    def test_values(self):
        assert DeviceRevocationReason.MANUAL == "manual"
        assert DeviceRevocationReason.ADMIN == "admin"
        assert DeviceRevocationReason.LOCKOUT == "lockout"
        assert DeviceRevocationReason.CLOSURE == "closure"
        assert DeviceRevocationReason.PASSWORD_CHANGED == "password_changed"
        assert DeviceRevocationReason.MFA_RECONFIGURED == "mfa_reconfigured"
        assert DeviceRevocationReason.LIMIT_EXCEEDED == "limit_exceeded"
