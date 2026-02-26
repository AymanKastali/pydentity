from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.models.role import Role
    from pydentity.domain.models.session import Session
    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import (
        EmailAddress,
        RoleId,
        SessionId,
        UserId,
    )


class UserRepository(ABC):
    @abstractmethod
    async def find_by_id(self, user_id: UserId) -> User | None: ...

    @abstractmethod
    async def find_by_email(self, email: EmailAddress) -> User | None: ...

    @abstractmethod
    async def save(self, user: User) -> None: ...


class SessionRepository(ABC):
    @abstractmethod
    async def find_by_id(self, session_id: SessionId) -> Session | None: ...

    @abstractmethod
    async def find_active_by_user_id(self, user_id: UserId) -> list[Session]: ...

    @abstractmethod
    async def save(self, session: Session) -> None: ...


class RoleRepository(ABC):
    @abstractmethod
    async def find_by_id(self, role_id: RoleId) -> Role | None: ...

    @abstractmethod
    async def find_by_ids(self, role_ids: frozenset[RoleId]) -> list[Role]: ...

    @abstractmethod
    async def save(self, role: Role) -> None: ...
