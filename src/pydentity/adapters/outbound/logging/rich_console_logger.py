from __future__ import annotations

from rich.console import Console

_LEVELS = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}

_LEVEL_STYLES: dict[str, str] = {
    "DEBUG": "dim",
    "INFO": "bold cyan",
    "WARNING": "bold yellow",
    "ERROR": "bold red",
}


class RichConsoleLogger:
    def __init__(
        self,
        console: Console | None = None,
        *,
        level: str = "DEBUG",
        show_locals: bool = False,
    ) -> None:
        self._console = console or Console(stderr=True)
        self._threshold = _LEVELS[level.upper()]
        self._show_locals = show_locals

    def debug(self, message: str, **kwargs: object) -> None:
        self._log("DEBUG", message, kwargs)

    def info(self, message: str, **kwargs: object) -> None:
        self._log("INFO", message, kwargs)

    def warning(self, message: str, **kwargs: object) -> None:
        self._log("WARNING", message, kwargs)

    def error(self, message: str, **kwargs: object) -> None:
        self._log("ERROR", message, kwargs)

    def exception(self, message: str, **kwargs: object) -> None:
        self._log("ERROR", message, kwargs)
        self._console.print_exception(show_locals=self._show_locals)

    def _log(self, level: str, message: str, context: dict[str, object]) -> None:
        if _LEVELS[level] < self._threshold:
            return
        args: list[object] = [message]
        if context:
            args.append(context)
        self._console.log(*args, style=_LEVEL_STYLES[level], _stack_offset=3)
