"""Main entry point for pydentity."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import uvicorn
from rich.logging import RichHandler

from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.inbound.api.app import create_app as _factory

if TYPE_CHECKING:
    from fastapi import FastAPI

logging.basicConfig(
    level=logging.DEBUG,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(
            rich_tracebacks=True,
            tracebacks_show_locals=True,
            show_time=True,
            show_path=True,
            markup=True,
        ),
    ],
)
logger = logging.getLogger("pydentity")


def create_app() -> FastAPI:
    """Lazy factory — imported by uvicorn via ``pydentity.main:create_app``."""
    return _factory()


def main() -> None:
    """Run the application."""
    settings = get_app_settings().fastapi
    logger.info("[bold green]pydentity[/bold green] is starting")
    uvicorn.run(
        "pydentity.main:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    main()
