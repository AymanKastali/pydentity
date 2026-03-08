from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI

from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.container import Container
from pydentity.adapters.inbound.api.exception_handlers import (
    register_exception_handlers,
)
from pydentity.adapters.inbound.api.middleware.trace import TraceMiddleware
from pydentity.adapters.inbound.api.routes import (
    account,
    auth,
    email,
    password,
    roles,
)
from pydentity.adapters.outbound.persistence.postgres.migrator import run_migrations

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    await run_migrations()
    container = Container.build()
    app.state.container = container

    await container.event_subscriber.start()
    try:
        yield
    finally:
        await container.event_subscriber.stop()
        await container.redis.aclose()


def create_app() -> FastAPI:
    settings = get_app_settings().fastapi

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )

    app.add_middleware(TraceMiddleware)

    register_exception_handlers(app)

    app.include_router(auth.router)
    app.include_router(account.router)
    app.include_router(email.router)
    app.include_router(password.router)
    app.include_router(roles.router)

    return app
