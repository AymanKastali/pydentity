from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

from pydentity.adapters.inbound.api.context import trace_id_var

if TYPE_CHECKING:
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import Response

    from pydentity.adapters.config.middleware import RequestLoggingSettings

_log = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: object, settings: RequestLoggingSettings) -> None:
        super().__init__(app)  # type: ignore[arg-type]
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

        client_ip = request.client.host if request.client else "unknown"
        trace_id = trace_id_var.get("")

        _log.info(
            "method=%s path=%s status=%d duration_ms=%.2f trace_id=%s client_ip=%s",
            request.method,
            path,
            response.status_code,
            duration_ms,
            trace_id,
            client_ip,
        )
        return response
