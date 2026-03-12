"""Standard-library logging bootstrap — Rich (dev) or JSON (prod)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydentity import __app_name__, __version__
from pydentity.adapters.config.app import get_app_settings
from pydentity.adapters.inbound.api.context import client_ip_var, trace_id_var
from pydentity.adapters.outbound.logging.stdlib_adapter import StdlibLoggerAdapter


class _RequestContextFilter(logging.Filter):
    """Injects trace_id, client_ip, and a default context dict into every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.trace_id = trace_id_var.get("")
        record.client_ip = client_ip_var.get("")
        if not hasattr(record, "context"):
            record.context = {}
        return True


def _build_log_entry(record: logging.LogRecord) -> dict[str, object]:
    """Build the canonical JSON log structure from a LogRecord."""
    from datetime import UTC, datetime

    context: dict[str, object] = getattr(record, "context", {})
    entry: dict[str, object] = {
        "logger": __app_name__,
        "version": __version__,
        "level": record.levelname,
        "message": record.getMessage(),
        "timestamp": datetime.now(UTC).isoformat(),
        "source": f"{record.pathname}:{record.lineno}",
    }
    trace_id: str = getattr(record, "trace_id", "")
    if trace_id:
        entry["trace_id"] = trace_id
    client_ip: str = getattr(record, "client_ip", "")
    if client_ip:
        entry["client_ip"] = client_ip
    if context:
        entry["context"] = context
    return entry


class _JsonHandler(logging.Handler):
    """Writes one JSON line per log record — for production log aggregators."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = _build_log_entry(record)
            line = json.dumps(entry, default=str)
            import sys

            sys.stderr.write(line + "\n")
            sys.stderr.flush()
        except Exception:
            self.handleError(record)


_LEVEL_STYLES: dict[str, str] = {
    "DEBUG": "dim blue",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "bold red",
    "CRITICAL": "bold white on red",
}


class _ColorHandler(logging.Handler):
    """Colored single-line logs via Rich Console — no table, no wrapping."""

    def __init__(self, level: int = logging.NOTSET) -> None:
        super().__init__(level)
        from rich.console import Console

        self._console = Console(stderr=True, force_terminal=True)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            from datetime import datetime

            ts = datetime.fromtimestamp(record.created).strftime("%X")
            lvl = record.levelname
            style = _LEVEL_STYLES.get(lvl, "")
            msg = record.getMessage()
            source = f"{Path(record.pathname).name}:{record.lineno}"

            parts: list[str] = [
                f"\\[{ts}]",
                f"[{style}]{lvl:<8}[/]",
                msg,
            ]

            trace_id: str = getattr(record, "trace_id", "")
            if trace_id:
                parts.append(f"[dim cyan]trace={trace_id}[/]")

            client_ip: str = getattr(record, "client_ip", "")
            if client_ip:
                parts.append(f"[dim magenta]ip={client_ip}[/]")

            context: dict[str, object] = getattr(record, "context", {})
            if context:
                from rich.pretty import pretty_repr

                parts.append(pretty_repr(context, expand_all=True))

            parts.append(f"[dim]{source}[/]")

            self._console.print(
                " ".join(parts), markup=True, highlight=True, soft_wrap=True
            )

            if record.exc_info and record.exc_info[1] is not None:
                from rich.traceback import Traceback

                tb = Traceback.from_exception(*record.exc_info, show_locals=True)
                self._console.print(tb)
        except Exception:
            self.handleError(record)


def setup_logging() -> StdlibLoggerAdapter:
    """Bootstrap stdlib logging and return an adapter satisfying ``LoggerPort``."""
    settings = get_app_settings()
    level = getattr(logging, settings.fastapi.log_level.upper(), logging.INFO)
    log_format = settings.fastapi.log_format.lower()

    if log_format == "json":
        handler: logging.Handler = _JsonHandler(level)
    else:
        handler = _ColorHandler(level)

    handler.addFilter(_RequestContextFilter())
    logging.basicConfig(level=level, handlers=[handler])

    # Force Uvicorn loggers through our unified handler so every log
    # line — including FastAPI/Uvicorn internals — uses the same format.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True

    stdlib_logger = logging.getLogger(settings.fastapi.app_name)
    return StdlibLoggerAdapter(stdlib_logger)
