from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from pydentity.shared_kernel import AccountId, IdentityId


@pytest.fixture
def fixed_uuid() -> UUID:
    return UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def another_uuid() -> UUID:
    return UUID("87654321-4321-8765-4321-876543218765")


@pytest.fixture
def account_id(fixed_uuid) -> AccountId:
    return AccountId(value=fixed_uuid)


@pytest.fixture
def identity_id() -> IdentityId:
    return IdentityId(value=UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def future(now) -> datetime:
    return now + timedelta(hours=1)


@pytest.fixture
def past(now) -> datetime:
    return now - timedelta(hours=1)


@pytest.fixture
def far_future(now) -> datetime:
    return now + timedelta(days=30)
