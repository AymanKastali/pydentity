from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.outbound.persistence.postgres.engine import (
    build_engine,
    build_session_factory,
)
from pydentity.adapters.outbound.persistence.postgres.unit_of_work import (
    SqlAlchemyUnitOfWork,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    return build_engine(get_app_settings().postgres)


@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return build_session_factory(get_engine())


def get_uow() -> SqlAlchemyUnitOfWork:
    return SqlAlchemyUnitOfWork(get_session_factory())
