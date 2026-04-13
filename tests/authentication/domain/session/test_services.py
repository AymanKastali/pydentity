from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from pydentity.authentication.domain.session.aggregate import Session
from pydentity.authentication.domain.session.events import SessionRevoked
from pydentity.authentication.domain.session.repository import SessionRepository
from pydentity.authentication.domain.session.services import RevokeSessions
from pydentity.authentication.domain.session.value_objects import (
    SessionExpiry,
    SessionId,
    SessionRevocationReason,
    SessionStatus,
)
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


def _make_active_session(device_id: DeviceId) -> Session:
    return Session.create(
        session_id=SessionId(value=uuid4()),
        account_id=AccountId(value=uuid4()),
        device_id=device_id,
        expiry=SessionExpiry(
            value=datetime.now(UTC) + timedelta(hours=1),
        ),
    )


def _make_repository(sessions: list[Session]) -> SessionRepository:
    repo = AsyncMock(spec=SessionRepository)
    repo.find_active_by_device_id.return_value = sessions
    return repo


class TestRevokeSessions:
    @pytest.mark.asyncio
    async def test_revokes_all_active_sessions(self):
        device_id = DeviceId(value=uuid4())
        sessions = [_make_active_session(device_id) for _ in range(3)]

        service = RevokeSessions(repository=_make_repository(sessions))
        await service.revoke_active_sessions(device_id, SessionRevocationReason.FORCED)

        for session in sessions:
            assert session.status == SessionStatus.REVOKED

    @pytest.mark.asyncio
    async def test_records_session_revoked_events(self):
        device_id = DeviceId(value=uuid4())
        sessions = [_make_active_session(device_id) for _ in range(2)]
        for session in sessions:
            session.clear_events()

        service = RevokeSessions(repository=_make_repository(sessions))
        await service.revoke_active_sessions(
            device_id, SessionRevocationReason.COMPROMISE
        )

        for session in sessions:
            events = session.events
            assert len(events) == 1
            assert isinstance(events[0], SessionRevoked)
            assert events[0].reason == SessionRevocationReason.COMPROMISE

    @pytest.mark.asyncio
    async def test_empty_list_does_nothing(self):
        device_id = DeviceId(value=uuid4())
        service = RevokeSessions(repository=_make_repository([]))
        await service.revoke_active_sessions(device_id, SessionRevocationReason.LOGOUT)

    @pytest.mark.asyncio
    async def test_skips_already_revoked_sessions(self):
        device_id = DeviceId(value=uuid4())
        active = _make_active_session(device_id)
        revoked = _make_active_session(device_id)
        revoked.revoke(SessionRevocationReason.LOGOUT)

        service = RevokeSessions(repository=_make_repository([active, revoked]))
        await service.revoke_active_sessions(device_id, SessionRevocationReason.EXPIRED)

        assert active.status == SessionStatus.REVOKED
