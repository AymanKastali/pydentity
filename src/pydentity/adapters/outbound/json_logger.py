from __future__ import annotations

import json
import sys
import traceback
from datetime import UTC, datetime
from typing import IO

from pydentity import __app_name__, __version__

_LEVELS = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}


class JsonLogger:
    """Production logger emitting one JSON object per line."""

    def __init__(
        self,
        *,
        stream: IO[str] | None = None,
        level: str = "DEBUG",
    ) -> None:
        self._stream = stream or sys.stderr
        self._threshold = _LEVELS[level.upper()]

    def debug(self, message: str, **kwargs: object) -> None:
        self._log("DEBUG", message, kwargs)

    def info(self, message: str, **kwargs: object) -> None:
        self._log("INFO", message, kwargs)

    def warning(self, message: str, **kwargs: object) -> None:
        self._log("WARNING", message, kwargs)

    def error(self, message: str, **kwargs: object) -> None:
        self._log("ERROR", message, kwargs)

    def exception(self, message: str, **kwargs: object) -> None:
        """Log at ERROR level with the current exception's traceback."""
        exc_info = sys.exc_info()
        ctx: dict[str, object] = dict(kwargs)
        if exc_info[0] is not None:
            ctx["traceback"] = "".join(traceback.format_exception(*exc_info))
        self._log("ERROR", message, ctx)

    # ------------------------------------------------------------------

    def _log(self, level: str, message: str, context: dict[str, object]) -> None:
        if _LEVELS[level] < self._threshold:
            return
        record = {
            "logger": __app_name__,
            "version": __version__,
            "level": level,
            "message": message,
            "timestamp": datetime.now(UTC).isoformat(),
            "context": context,
        }
        self._stream.write(json.dumps(record, default=str) + "\n")
        self._stream.flush()
