from datetime import datetime
from uuid import uuid4

import pytest

from pydentity.authentication.domain.session.aggregate import Session
from pydentity.authentication.domain.session.aggregate_id import SessionId
from pydentity.authentication.domain.session.value_objects import RefreshToken
from pydentity.shared_kernel import AccountId


@pytest.fixture
def session_id() -> SessionId:
    return SessionId(value=uuid4())


@pytest.fixture
def refresh_token(far_future: datetime) -> RefreshToken:
    return RefreshToken(
        token_hash="$hash_of_refresh_token",
        expires_at=far_future,
        is_revoked=False,
    )


@pytest.fixture
def new_refresh_token(far_future: datetime) -> RefreshToken:
    return RefreshToken(
        token_hash="$hash_of_new_refresh_token",
        expires_at=far_future,
        is_revoked=False,
    )


@pytest.fixture
def expired_refresh_token(past: datetime) -> RefreshToken:
    return RefreshToken(
        token_hash="$hash_expired",
        expires_at=past,
        is_revoked=False,
    )


@pytest.fixture
def revoked_refresh_token(far_future: datetime) -> RefreshToken:
    return RefreshToken(
        token_hash="$hash_revoked",
        expires_at=far_future,
        is_revoked=True,
    )


@pytest.fixture
def active_session(
    session_id: SessionId,
    account_id: AccountId,
    refresh_token: RefreshToken,
    now: datetime,
) -> Session:
    session = Session.start(session_id, account_id, refresh_token, now)
    session.clear_events()
    return session


@pytest.fixture
def ended_session(active_session: Session, now: datetime) -> Session:
    active_session.end(now)
    active_session.clear_events()
    return active_session
