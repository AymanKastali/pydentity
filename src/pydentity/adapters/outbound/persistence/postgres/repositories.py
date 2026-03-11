from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlmodel import col

# Mappers and Models
from pydentity.adapters.outbound.persistence.postgres.mappers import (
    device_to_model,
    model_to_device,
    model_to_role,
    model_to_session,
    model_to_user,
    role_to_model,
    session_to_model,
    user_to_model,
)
from pydentity.adapters.outbound.persistence.postgres.models import (
    DeviceModel,
    RoleModel,
    SessionModel,
    UserModel,
)
from pydentity.application.exceptions import PersistenceConsistencyError
from pydentity.domain.models.enums import DeviceStatus, SessionStatus

# Ports
from pydentity.domain.ports.repositories import (
    DeviceRepositoryPort,
    RoleRepositoryPort,
    SessionRepositoryPort,
    UserRepositoryPort,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm.attributes import QueryableAttribute

    from pydentity.domain.models.device import Device
    from pydentity.domain.models.role import Role
    from pydentity.domain.models.session import Session
    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import (
        DeviceFingerprint,
        DeviceId,
        EmailAddress,
        HashedVerificationToken,
        RoleName,
        SessionId,
        UserId,
    )

# ── User Repository ───────────────────────────────────────────────────────────


class PostgresUserRepository(UserRepositoryPort):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def find_by_id(self, user_id: UserId) -> User | None:
        stmt = (
            select(UserModel)
            .where(col(UserModel.domain_id) == user_id.value)
            .options(selectinload(cast("QueryableAttribute[Any]", UserModel.roles)))
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return model_to_user(model) if model else None

    async def find_by_email(self, email: EmailAddress) -> User | None:
        stmt = (
            select(UserModel)
            .where(col(UserModel.email) == email.address)
            .options(selectinload(cast("QueryableAttribute[Any]", UserModel.roles)))
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return model_to_user(model) if model else None

    async def find_by_verification_token_hash(
        self, token_hash: HashedVerificationToken
    ) -> User | None:
        stmt = (
            select(UserModel)
            .where(col(UserModel.email_verification_token_hash) == token_hash.value)
            .options(selectinload(cast("QueryableAttribute[Any]", UserModel.roles)))
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return model_to_user(model) if model else None

    async def upsert(self, user: User) -> None:
        # Fetch with roles to ensure the relationship collection is managed correctly
        stmt = (
            select(UserModel)
            .where(col(UserModel.domain_id) == user.id.value)
            .options(selectinload(cast("QueryableAttribute[Any]", UserModel.roles)))
        )
        existing = (await self._session.execute(stmt)).scalar_one_or_none()

        # Domain -> Model transformation
        model_data = user_to_model(user)

        if existing:
            # Update attributes on the tracked instance
            data = model_data.model_dump(exclude={"id", "roles", "sessions", "devices"})
            for key, value in data.items():
                setattr(existing, key, value)
            model = existing
        else:
            model = model_data
            self._session.add(model)

        # Sync Roles Relationship
        if user.role_names:
            role_stmt = select(RoleModel).where(
                col(RoleModel.name).in_([r.value for r in user.role_names])
            )
            roles_res = await self._session.execute(role_stmt)
            model.roles = list(roles_res.scalars().all())
        else:
            model.roles = []

        await self._session.flush()


# ── Role Repository ───────────────────────────────────────────────────────────


class PostgresRoleRepository(RoleRepositoryPort):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def find_by_name(self, name: RoleName) -> Role | None:
        stmt = select(RoleModel).where(col(RoleModel.name) == name.value)
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return model_to_role(model) if model else None

    async def find_by_names(self, names: frozenset[RoleName]) -> list[Role]:
        stmt = select(RoleModel).where(
            col(RoleModel.name).in_([r.value for r in names])
        )
        result = await self._session.execute(stmt)
        return [model_to_role(m) for m in result.scalars().all()]

    async def upsert(self, role: Role) -> None:
        stmt = select(RoleModel).where(col(RoleModel.name) == role.id.value)
        existing = (await self._session.execute(stmt)).scalar_one_or_none()

        model_data = role_to_model(role)
        if existing:
            for key, value in model_data.model_dump(exclude={"id", "users"}).items():
                setattr(existing, key, value)
        else:
            self._session.add(model_data)

        await self._session.flush()


# ── Device Repository ─────────────────────────────────────────────────────────


class PostgresDeviceRepository(DeviceRepositoryPort):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def upsert(self, device: Device) -> None:
        # Resolve integer FK for the user
        user_fk_stmt = select(col(UserModel.id)).where(
            col(UserModel.domain_id) == device.user_id.value
        )
        user_fk = (await self._session.execute(user_fk_stmt)).scalar_one_or_none()
        if user_fk is None:
            raise PersistenceConsistencyError(
                detail=f"UserModel.id not found for domain_id={device.user_id.value}"
            )

        stmt = select(DeviceModel).where(col(DeviceModel.domain_id) == device.id.value)
        existing = (await self._session.execute(stmt)).scalar_one_or_none()

        model_data = device_to_model(device, user_fk=user_fk)
        if existing:
            for key, value in model_data.model_dump(
                exclude={"id", "user", "sessions"}
            ).items():
                setattr(existing, key, value)
        else:
            self._session.add(model_data)

        await self._session.flush()

    async def get_by_id(self, device_id: DeviceId) -> Device | None:
        stmt = select(DeviceModel).where(col(DeviceModel.domain_id) == device_id.value)
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return model_to_device(model) if model else None

    async def get_all_for_user(self, user_id: UserId) -> list[Device]:
        stmt = select(DeviceModel).where(
            col(DeviceModel.user_domain_id) == user_id.value
        )
        result = await self._session.execute(stmt)
        return [model_to_device(m) for m in result.scalars().all()]

    async def revoke_all_for_user(self, user_id: UserId) -> None:
        stmt = select(DeviceModel).where(
            col(DeviceModel.user_domain_id) == user_id.value
        )
        result = await self._session.execute(stmt)
        for m in result.scalars().all():
            m.status = DeviceStatus.REVOKED.value
        await self._session.flush()

    async def find_by_fingerprint(
        self, user_id: UserId, fingerprint: DeviceFingerprint
    ) -> Device | None:
        stmt = select(DeviceModel).where(
            col(DeviceModel.user_domain_id) == user_id.value,
            col(DeviceModel.fingerprint) == fingerprint.value,
        )
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return model_to_device(model) if model else None


# ── Session Repository ────────────────────────────────────────────────────────


class PostgresSessionRepository(SessionRepositoryPort):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def upsert(self, session: Session) -> None:
        # Resolve both integer FKs for data integrity
        u_stmt = select(col(UserModel.id)).where(
            col(UserModel.domain_id) == session.user_id.value
        )
        d_stmt = select(col(DeviceModel.id)).where(
            col(DeviceModel.domain_id) == session.device_id.value
        )

        user_fk = (await self._session.execute(u_stmt)).scalar_one_or_none()
        if user_fk is None:
            raise PersistenceConsistencyError(
                detail=f"UserModel.id not found for domain_id={session.user_id.value}"
            )
        device_fk = (await self._session.execute(d_stmt)).scalar_one_or_none()
        if device_fk is None:
            raise PersistenceConsistencyError(
                detail=f"DeviceModel.id not found for domain_id="
                f"{session.device_id.value}"
            )

        stmt = select(SessionModel).where(
            col(SessionModel.domain_id) == session.id.value
        )
        existing = (await self._session.execute(stmt)).scalar_one_or_none()

        model_data = session_to_model(session, user_fk=user_fk, device_fk=device_fk)
        if existing:
            for key, value in model_data.model_dump(
                exclude={"id", "user", "device"}
            ).items():
                setattr(existing, key, value)
        else:
            self._session.add(model_data)

        await self._session.flush()

    async def find_by_id(self, session_id: SessionId) -> Session | None:
        stmt = select(SessionModel).where(
            col(SessionModel.domain_id) == session_id.value
        )
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return model_to_session(model) if model else None

    async def get_active_by_device(self, device_id: DeviceId) -> Session | None:
        stmt = select(SessionModel).where(
            col(SessionModel.device_domain_id) == device_id.value,
            col(SessionModel.status) == SessionStatus.ACTIVE.value,
        )
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return model_to_session(model) if model else None

    async def find_active_by_user_id(self, user_id: UserId) -> list[Session]:
        stmt = select(SessionModel).where(
            col(SessionModel.user_domain_id) == user_id.value,
            col(SessionModel.status) == SessionStatus.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        return [model_to_session(m) for m in result.scalars().all()]
