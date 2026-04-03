from datetime import datetime

import pytest

from pydentity.authentication.domain.account.aggregate import Account
from pydentity.authentication.domain.account.value_objects import (
    EmailAddress,
    EncryptedTOTPSecret,
    HashedPassword,
    HashedRecoveryCode,
    HashedRecoveryCodeSet,
    LockoutPolicy,
    PasswordPolicy,
)
from pydentity.shared_kernel import AccountId, IdentityId


@pytest.fixture
def valid_email() -> EmailAddress:
    return EmailAddress(value="user@example.com")


@pytest.fixture
def hashed_password() -> HashedPassword:
    return HashedPassword(value="$argon2id$hashed_value_here")


@pytest.fixture
def another_hashed_password() -> HashedPassword:
    return HashedPassword(value="$argon2id$another_hashed_value")


@pytest.fixture
def totp_secret() -> EncryptedTOTPSecret:
    return EncryptedTOTPSecret(value=b"encrypted_totp_secret_bytes")


@pytest.fixture
def unused_recovery_code() -> HashedRecoveryCode:
    return HashedRecoveryCode(value="$argon2id$recovery_code_1", used_at=None)


@pytest.fixture
def recovery_code_set(unused_recovery_code) -> HashedRecoveryCodeSet:
    return HashedRecoveryCodeSet(codes=(unused_recovery_code,))


@pytest.fixture
def password_policy() -> PasswordPolicy:
    return PasswordPolicy(
        min_length=8,
        max_length=128,
        require_uppercase=True,
        require_lowercase=True,
        require_digit=True,
        require_special=True,
        history_depth=5,
    )


@pytest.fixture
def lockout_policy() -> LockoutPolicy:
    return LockoutPolicy(threshold=5, tier_minutes=(5, 15, 60))


@pytest.fixture
def registered_account(
    account_id: AccountId,
    identity_id: IdentityId,
    valid_email: EmailAddress,
    hashed_password: HashedPassword,
    now: datetime,
) -> Account:
    account = Account.register(
        account_id, identity_id, valid_email, hashed_password, now
    )
    account.clear_events()
    return account


@pytest.fixture
def active_account(registered_account: Account, now: datetime) -> Account:
    registered_account.verify_email(now)
    registered_account.clear_events()
    return registered_account


@pytest.fixture
def active_account_with_totp(
    active_account: Account,
    totp_secret: EncryptedTOTPSecret,
    now: datetime,
) -> Account:
    active_account.add_totp_secret(totp_secret, now)
    active_account.clear_events()
    return active_account


@pytest.fixture
def active_account_with_mfa(
    active_account_with_totp: Account,
    recovery_code_set: HashedRecoveryCodeSet,
    now: datetime,
) -> Account:
    active_account_with_totp.add_recovery_codes(recovery_code_set, now)
    active_account_with_totp.enable_mfa(now)
    active_account_with_totp.clear_events()
    return active_account_with_totp


@pytest.fixture
def locked_account(active_account: Account, now: datetime) -> Account:
    active_account.lock(now)
    active_account.clear_events()
    return active_account


@pytest.fixture
def suspended_account(active_account: Account, now: datetime) -> Account:
    active_account.suspend(now)
    active_account.clear_events()
    return active_account


@pytest.fixture
def closed_account(active_account: Account, now: datetime) -> Account:
    active_account.close(now)
    active_account.clear_events()
    return active_account
