"""Main entry point for pydentity."""

from __future__ import annotations

from typing import TYPE_CHECKING

import uvicorn

from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.inbound.api.app import create_app as _factory
from pydentity.adapters.outbound.logging.setup import setup_logging

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = setup_logging()


def create_app() -> FastAPI:
    """Lazy factory — imported by uvicorn via ``pydentity.main:create_app``."""
    return _factory()


def main() -> None:
    """Run the application."""
    app_settings = get_app_settings()
    fastapi = app_settings.fastapi
    logger.info("[bold green]pydentity[/bold green] is starting")
    uvicorn.run(
        "pydentity.main:create_app",
        factory=True,
        host=fastapi.host,
        port=fastapi.port,
        reload=fastapi.reload,
        reload_dirs=["src/pydentity"] if fastapi.reload else [],
        log_level=app_settings.logging.level,
    )


if __name__ == "__main__":
    main()
