from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp

    from pydentity.adapters.config.middleware import RequestLoggingSettings

_log = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: RequestLoggingSettings) -> None:
        super().__init__(app)
        self._excluded_paths = set(settings.excluded_paths)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path
        if path in self._excluded_paths:
            return await call_next(request)

        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        record: dict[str, object] = {
            "method": request.method,
            "path": path,
            "status": response.status_code,
            "duration_ms": duration_ms,
            "host": request.headers.get("host", "-"),
            "user_agent": request.headers.get("user-agent", "-"),
            "res_size": response.headers.get("content-length", "-"),
        }
        query = str(request.url.query)
        if query:
            record["query"] = query

        _log.info("request completed", extra={"context": record})
        return response
