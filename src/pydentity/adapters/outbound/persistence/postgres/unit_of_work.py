from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.adapters.outbound.persistence.postgres.repositories import (
    PostgresDeviceRepository,
    PostgresRoleRepository,
    PostgresSessionRepository,
    PostgresUserRepository,
)
from pydentity.domain.ports.unit_of_work import UnitOfWork

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_NOT_OPEN = "UnitOfWork is not active. Use it as: async with uow: ..."


class SqlAlchemyUnitOfWork(UnitOfWork):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

        # Explicit naming to match Postgres implementation
        self._users: PostgresUserRepository | None = None
        self._sessions: PostgresSessionRepository | None = None
        self._devices: PostgresDeviceRepository | None = None
        self._roles: PostgresRoleRepository | None = None

    # ── Repositories ──────────────────────────────────────────────────────

    @property
    def users(self) -> PostgresUserRepository:
        if self._users is None:
            raise RuntimeError(_NOT_OPEN)
        return self._users

    @property
    def sessions(self) -> PostgresSessionRepository:
        if self._sessions is None:
            raise RuntimeError(_NOT_OPEN)
        return self._sessions

    @property
    def devices(self) -> PostgresDeviceRepository:
        if self._devices is None:
            raise RuntimeError(_NOT_OPEN)
        return self._devices

    @property
    def roles(self) -> PostgresRoleRepository:
        if self._roles is None:
            raise RuntimeError(_NOT_OPEN)
        return self._roles

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def __aenter__(self) -> SqlAlchemyUnitOfWork:
        self._session = self._session_factory()

        # Injecting the active session into repositories
        self._users = PostgresUserRepository(self._session)
        self._sessions = PostgresSessionRepository(self._session)
        self._devices = PostgresDeviceRepository(self._session)
        self._roles = PostgresRoleRepository(self._session)

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._session is None:
            return  # Already closed

        try:
            if exc_type:
                await self.rollback()
            # Note: Many UoW patterns prefer explicit commit in service layer
            # rather than auto-committing on success in __aexit__.
        finally:
            await self._session.close()
            self._session = None
            self._users = None
            self._sessions = None
            self._devices = None
            self._roles = None

    # ── Transaction Control ───────────────────────────────────────────────

    async def commit(self) -> None:
        if self._session is None:
            raise RuntimeError(_NOT_OPEN)
        await self._session.commit()

    async def rollback(self) -> None:
        if self._session is None:
            raise RuntimeError(_NOT_OPEN)
        await self._session.rollback()
