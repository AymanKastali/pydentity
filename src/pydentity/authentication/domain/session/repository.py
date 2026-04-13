from abc import ABC, abstractmethod

from pydentity.authentication.domain.session.aggregate import Session
from pydentity.authentication.domain.session.value_objects import SessionId
from pydentity.shared_kernel.value_objects import DeviceId


class SessionRepository(ABC):
    @abstractmethod
    async def save(self, session: Session) -> None: ...

    @abstractmethod
    async def find_by_id(self, session_id: SessionId) -> Session | None: ...

    @abstractmethod
    async def find_active_by_device_id(self, device_id: DeviceId) -> list[Session]: ...
