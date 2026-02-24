from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import RoleId, SessionId, UserId


class IdentityGeneratorPort(ABC):
    @abstractmethod
    def new_user_id(self) -> UserId: ...

    @abstractmethod
    def new_session_id(self) -> SessionId: ...

    @abstractmethod
    def new_jti(self) -> str: ...

    @abstractmethod
    def new_role_id(self) -> RoleId: ...
