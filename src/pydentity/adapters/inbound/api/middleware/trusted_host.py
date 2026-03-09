from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.trustedhost import TrustedHostMiddleware

if TYPE_CHECKING:
    from fastapi import FastAPI

    from pydentity.adapters.config.middleware import TrustedHostSettings


def add_trusted_host_middleware(app: FastAPI, settings: TrustedHostSettings) -> None:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts,
    )
