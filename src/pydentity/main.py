"""Main entry point for pydentity."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import uvicorn
from rich.logging import RichHandler

from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.inbound.api.app import create_app as _factory
from pydentity.adapters.inbound.api.context import trace_id_var

if TYPE_CHECKING:
    from fastapi import FastAPI


class TraceFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        tid = trace_id_var.get("")
        record.trace_id = f"[{tid}] " if tid else ""
        return True


def _setup_logging() -> logging.Logger:
    settings = get_app_settings().fastapi
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    show_locals = level == logging.DEBUG

    handler = RichHandler(
        rich_tracebacks=True,
        tracebacks_show_locals=show_locals,
        show_time=True,
        show_path=True,
        markup=True,
    )
    handler.addFilter(TraceFilter())

    logging.basicConfig(
        level=level,
        format="%(trace_id)s%(message)s",
        datefmt="[%X]",
        handlers=[handler],
    )
    return logging.getLogger("pydentity")


logger = _setup_logging()


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
