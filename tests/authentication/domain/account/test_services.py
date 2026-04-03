from datetime import datetime
from uuid import uuid4

import pytest

from pydentity.authentication.domain.account.aggregate import Account
from pydentity.authentication.domain.account.errors import (
    EmailAlreadyTakenError,
    PasswordReuseError,
)
from pydentity.authentication.domain.account.repository import AccountRepository
from pydentity.authentication.domain.account.services import (
    PreventDuplicateEmail,
    PreventPasswordReuse,
)
from pydentity.authentication.domain.account.value_objects import (
    EmailAddress,
    HashedPassword,
    HashedPasswordHistory,
)
from pydentity.shared_kernel import AccountId, IdentityId

# --- Fake repository ---


class FakeAccountRepository(AccountRepository):
    def __init__(self, existing_account: Account | None = None) -> None:
        self._existing_account = existing_account

    async def save(self, account: Account) -> None:
        pass

    async def find_by_id(self, account_id: AccountId) -> Account | None:
        return None

    async def find_by_email(self, email: EmailAddress) -> Account | None:
        return self._existing_account

    async def find_by_identity_id(self, identity_id: IdentityId) -> Account | None:
        return None


# --- PreventPasswordReuse ---


class TestPreventPasswordReuse:
    def _make_verifier(self, matching_hash: str | None = None):
        def verifier(raw_password: str, hashed: HashedPassword) -> bool:
            if matching_hash is None:
                return False
            return hashed.value == matching_hash

        return verifier

    def test_passes_with_new_password(self):
        current = HashedPassword(value="$current")
        history = HashedPasswordHistory.initialize()
        verifier = self._make_verifier(matching_hash=None)
        PreventPasswordReuse.check("new_password", current, history, verifier)

    def test_raises_when_matches_current_password(self):
        current = HashedPassword(value="$current")
        history = HashedPasswordHistory.initialize()
        verifier = self._make_verifier(matching_hash="$current")
        with pytest.raises(PasswordReuseError):
            PreventPasswordReuse.check("old_password", current, history, verifier)

    def test_raises_when_matches_history_entry(self):
        current = HashedPassword(value="$current")
        old = HashedPassword(value="$old")
        history = HashedPasswordHistory(hashes=(old,))
        verifier = self._make_verifier(matching_hash="$old")
        with pytest.raises(PasswordReuseError):
            PreventPasswordReuse.check("old_password", current, history, verifier)

    def test_checks_current_before_history(self):
        call_order: list[str] = []

        def verifier(raw_password: str, hashed: HashedPassword) -> bool:
            call_order.append(hashed.value)
            return False

        current = HashedPassword(value="$current")
        old = HashedPassword(value="$old")
        history = HashedPasswordHistory(hashes=(old,))
        PreventPasswordReuse.check("new", current, history, verifier)
        assert call_order == ["$current", "$old"]


# --- PreventDuplicateEmail ---


class TestPreventDuplicateEmail:
    async def test_passes_when_email_not_taken(self):
        email = EmailAddress(value="new@example.com")
        repository = FakeAccountRepository(existing_account=None)
        await PreventDuplicateEmail.check(email, repository)

    async def test_raises_when_email_taken(self, now: datetime):
        email = EmailAddress(value="taken@example.com")
        existing = Account.register(
            AccountId(value=uuid4()),
            IdentityId(value=uuid4()),
            email,
            HashedPassword(value="$hash"),
            now,
        )
        repository = FakeAccountRepository(existing_account=existing)
        with pytest.raises(EmailAlreadyTakenError):
            await PreventDuplicateEmail.check(email, repository)
