from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.models.device import Device
    from pydentity.domain.models.role import Role
    from pydentity.domain.models.session import Session
    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import (
        DeviceFingerprint,
        DeviceId,
        EmailAddress,
        HashedRefreshToken,
        HashedResetToken,
        HashedVerificationToken,
        RoleName,
        SessionId,
        UserId,
    )


class UserRepositoryPort(ABC):
    @abstractmethod
    async def find_by_id(self, user_id: UserId) -> User | None: ...

    @abstractmethod
    async def find_by_email(self, email: EmailAddress) -> User | None: ...

    @abstractmethod
    async def find_by_verification_token_hash(
        self, token_hash: HashedVerificationToken
    ) -> User | None: ...

    @abstractmethod
    async def find_by_reset_token_hash(
        self, token_hash: HashedResetToken
    ) -> User | None: ...

    @abstractmethod
    async def check_email_exists(self, email: EmailAddress) -> bool: ...

    @abstractmethod
    async def upsert(self, user: User) -> None: ...


class SessionRepositoryPort(ABC):
    @abstractmethod
    async def find_by_id(self, session_id: SessionId) -> Session | None: ...

    @abstractmethod
    async def find_by_refresh_token_hash(
        self, token_hash: HashedRefreshToken
    ) -> Session | None: ...

    @abstractmethod
    async def find_active_by_device(self, device_id: DeviceId) -> Session | None: ...

    @abstractmethod
    async def find_active_by_user_id(self, user_id: UserId) -> list[Session]: ...

    @abstractmethod
    async def upsert(self, session: Session) -> None: ...


class RoleRepositoryPort(ABC):
    @abstractmethod
    async def find_by_name(self, name: RoleName) -> Role | None: ...

    @abstractmethod
    async def find_by_names(self, names: frozenset[RoleName]) -> list[Role]: ...

    @abstractmethod
    async def check_name_exists(self, name: RoleName) -> bool: ...

    @abstractmethod
    async def upsert(self, role: Role) -> None: ...


class DeviceRepositoryPort(ABC):
    @abstractmethod
    async def upsert(self, device: Device) -> None: ...

    @abstractmethod
    async def find_by_id(self, device_id: DeviceId) -> Device | None: ...

    @abstractmethod
    async def find_all_for_user(self, user_id: UserId) -> list[Device]: ...

    @abstractmethod
    async def find_by_fingerprint(
        self, user_id: UserId, fingerprint: DeviceFingerprint
    ) -> Device | None: ...

    @abstractmethod
    async def check_fingerprint_exists(
        self, user_id: UserId, fingerprint: DeviceFingerprint
    ) -> bool: ...
