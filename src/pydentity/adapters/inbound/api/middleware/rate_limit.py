from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import Response

    from pydentity.adapters.config.middleware import RateLimitSettings
    from pydentity.application.ports.rate_limit_store import RateLimitStorePort

_log = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: object,
        store: RateLimitStorePort,
        settings: RateLimitSettings,
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._store = store
        self._auth_paths = set(settings.auth_paths)
        self._auth_limit = settings.auth_limit
        self._auth_window = settings.auth_window_seconds
        self._general_limit = settings.general_limit
        self._general_window = settings.general_window_seconds

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        if path in self._auth_paths:
            limit = self._auth_limit
            window = self._auth_window
            key = f"rl:auth:{client_ip}"
        else:
            limit = self._general_limit
            window = self._general_window
            key = f"rl:general:{client_ip}"

        allowed, remaining, retry_after = await self._store.is_allowed(
            key=key,
            limit=limit,
            window_seconds=window,
        )

        if not allowed:
            _log.warning(
                "rate limit exceeded for %s on %s",
                client_ip,
                path,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "Too many requests. Please try again later.",
                    },
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
