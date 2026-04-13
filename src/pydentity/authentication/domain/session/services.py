from pydentity.authentication.domain.session.repository import SessionRepository
from pydentity.authentication.domain.session.value_objects import (
    SessionRevocationReason,
    SessionStatus,
)
from pydentity.shared_kernel.value_objects import DeviceId


class RevokeSessions:
    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    async def revoke_active_sessions(
        self, device_id: DeviceId, reason: SessionRevocationReason
    ) -> None:
        sessions = await self._repository.find_active_by_device_id(device_id)
        for session in sessions:
            if session.status is SessionStatus.ACTIVE:
                session.revoke(reason)
