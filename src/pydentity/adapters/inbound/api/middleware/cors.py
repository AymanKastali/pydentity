from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.middleware.cors import CORSMiddleware

if TYPE_CHECKING:
    from fastapi import FastAPI

    from pydentity.adapters.config.middleware import CorsSettings


def add_cors_middleware(app: FastAPI, settings: CorsSettings) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=settings.allowed_methods,
        allow_headers=settings.allowed_headers,
        allow_credentials=settings.allow_credentials,
        max_age=settings.max_age,
    )
