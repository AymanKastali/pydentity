from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI
from redis.asyncio import Redis

from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.container import Container
from pydentity.adapters.inbound.api.exception_handlers import (
    register_exception_handlers,
)
from pydentity.adapters.inbound.api.middleware.cors import add_cors_middleware
from pydentity.adapters.inbound.api.middleware.rate_limit import RateLimitMiddleware
from pydentity.adapters.inbound.api.middleware.request_logging import (
    RequestLoggingMiddleware,
)
from pydentity.adapters.inbound.api.middleware.security_headers import (
    SecurityHeadersMiddleware,
)
from pydentity.adapters.inbound.api.middleware.trace import TraceMiddleware
from pydentity.adapters.inbound.api.middleware.trusted_host import (
    add_trusted_host_middleware,
)
from pydentity.adapters.inbound.api.routes import (
    account,
    auth,
    email,
    password,
    roles,
)
from pydentity.adapters.outbound.persistence.postgres.container import get_uow
from pydentity.adapters.outbound.persistence.postgres.migrator import run_migrations
from pydentity.adapters.outbound.persistence.postgres.seeder import (
    seed_roles,
    seed_super_admin,
)
from pydentity.adapters.outbound.redis_rate_limit_store import RedisRateLimitStore

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

_log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    try:
        await run_migrations()
    except Exception:
        _log.exception("failed to run database migrations")
        raise

    container = Container.build()
    app.state.container = container

    settings = get_app_settings()

    try:
        await seed_roles(
            uow_factory=get_uow,
        )

        await seed_super_admin(
            uow_factory=get_uow,
            identity_generator=container.identity_generator,
            password_hasher=container.password_hasher,
            password_policy=container.password_policy,
            super_admin_settings=settings.super_admin,
        )
    except Exception:
        _log.exception("failed to seed database")
        raise

    rate_limit_redis: Redis | None = None
    if settings.middleware.rate_limit.enabled:
        try:
            rate_limit_redis = Redis.from_url(
                settings.redis.url,
                decode_responses=True,
            )
            app.state.rate_limit_store = RedisRateLimitStore(rate_limit_redis)
            _log.info("rate-limit Redis connection established")
        except Exception:
            _log.exception(
                "failed to connect to rate-limit Redis — rate limiting disabled",
            )
            rate_limit_redis = None

    try:
        await container.event_subscriber.start()
    except Exception:
        _log.warning(
            "failed to start event subscriber — events will not be processed",
            exc_info=True,
        )

    try:
        yield
    finally:
        await container.event_subscriber.stop()
        await container.redis.aclose()
        if rate_limit_redis is not None:
            await rate_limit_redis.aclose()
            _log.info("rate-limit Redis connection closed")


def create_app() -> FastAPI:
    settings = get_app_settings()

    app = FastAPI(
        title=settings.fastapi.app_name,
        version=settings.fastapi.app_version,
        lifespan=lifespan,
    )

    mw = settings.middleware

    # Registration order is bottom-up (Starlette reverses):
    # 1. TraceMiddleware (innermost — runs first on request)
    app.add_middleware(TraceMiddleware)

    # 2. RequestLoggingMiddleware
    app.add_middleware(RequestLoggingMiddleware, settings=mw.request_logging)

    # 3. RateLimitMiddleware (store injected during lifespan)
    if mw.rate_limit.enabled:
        app.add_middleware(
            RateLimitMiddleware,
            store=_LazyRateLimitStore(app),
            settings=mw.rate_limit,
        )

    # 4. SecurityHeadersMiddleware
    app.add_middleware(SecurityHeadersMiddleware, settings=mw.security_headers)

    # 5. CORSMiddleware
    add_cors_middleware(app, mw.cors)

    # 6. TrustedHostMiddleware (outermost — runs last on request)
    add_trusted_host_middleware(app, mw.trusted_host)

    register_exception_handlers(app)

    app.include_router(auth.router)
    app.include_router(account.router)
    app.include_router(email.router)
    app.include_router(password.router)
    app.include_router(roles.router)

    return app


class _LazyRateLimitStore:
    """Proxy that defers to ``app.state.rate_limit_store`` set during lifespan."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    async def is_allowed(
        self, *, key: str, limit: int, window_seconds: int
    ) -> tuple[bool, int, int]:
        store: RedisRateLimitStore | None = getattr(
            self._app.state,
            "rate_limit_store",
            None,
        )
        if store is None:
            return (True, limit, 0)
        return await store.is_allowed(
            key=key,
            limit=limit,
            window_seconds=window_seconds,
        )
