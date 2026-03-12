"""Thin adapter: satisfies LoggerPort by delegating to stdlib logging."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging


class StdlibLoggerAdapter:
    """Bridge between the application's LoggerPort and stdlib logging.

    Converts ``**kwargs`` from use-case call-sites into
    ``extra={"context": {...}}`` so formatters can include structured data.
    """

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def debug(self, message: str, **kwargs: object) -> None:
        self._logger.debug(message, extra={"context": kwargs}, stacklevel=2)

    def info(self, message: str, **kwargs: object) -> None:
        self._logger.info(message, extra={"context": kwargs}, stacklevel=2)

    def warning(self, message: str, **kwargs: object) -> None:
        self._logger.warning(message, extra={"context": kwargs}, stacklevel=2)

    def error(self, message: str, **kwargs: object) -> None:
        self._logger.error(message, extra={"context": kwargs}, stacklevel=2)

    def exception(self, message: str, **kwargs: object) -> None:
        self._logger.exception(message, extra={"context": kwargs}, stacklevel=2)
