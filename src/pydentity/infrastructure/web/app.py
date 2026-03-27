from fastapi import FastAPI

from pydentity.infrastructure.container import Container
from pydentity.infrastructure.database import (
    create_engine,
    create_session_factory,
)
from pydentity.infrastructure.settings import Settings
from pydentity.infrastructure.web.dependencies import (
    set_container,
    set_session_factory,
)
from pydentity.infrastructure.web.exception_handlers import (
    register_exception_handlers,
)
from pydentity.infrastructure.web.routes.auth import router as auth_router
from pydentity.infrastructure.web.routes.health import (
    router as health_router,
)


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = Settings()

    application = FastAPI(title="pydentity", version="0.1.0")

    engine = create_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    set_session_factory(session_factory)

    container = Container(settings)
    set_container(container)

    register_exception_handlers(application)
    application.include_router(health_router)
    application.include_router(auth_router)

    return application
