from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

    from pydentity.adapters.config.postgres import PostgresSettings


def build_engine(settings: PostgresSettings) -> AsyncEngine:
    return create_async_engine(
        str(settings.dsn),
        pool_size=settings.pool_size,
        max_overflow=settings.max_overflow,
        pool_recycle=settings.pool_recycle,
        pool_pre_ping=True,  # detects stale connections before use
        echo=settings.echo,
    )


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=engine,
        expire_on_commit=False,  # avoids lazy-load errors after commit
        autoflush=False,
        autocommit=False,
    )
