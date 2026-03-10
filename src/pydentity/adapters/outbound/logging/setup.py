"""Standard-library logging bootstrap (RichHandler + request context)."""

from __future__ import annotations

import logging

from rich.logging import RichHandler

from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.inbound.api.context import client_ip_var, trace_id_var


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        tid = trace_id_var.get("")
        ip = client_ip_var.get("")
        record.trace_id = f"[{tid}] " if tid else ""
        record.client_ip = f"[{ip}] " if ip else ""
        return True


def setup_logging() -> logging.Logger:
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
    handler.addFilter(RequestContextFilter())

    logging.basicConfig(
        level=level,
        format="%(trace_id)s%(client_ip)s%(message)s",
        datefmt="[%X]",
        handlers=[handler],
    )
    return logging.getLogger(settings.app_name)
