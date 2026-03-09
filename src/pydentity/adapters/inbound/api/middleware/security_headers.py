from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import Response

    from pydentity.adapters.config.middleware import SecurityHeadersSettings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: object, settings: SecurityHeadersSettings) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._headers: dict[str, str] = {
            "X-Content-Type-Options": settings.x_content_type_options,
            "X-Frame-Options": settings.x_frame_options,
            "Strict-Transport-Security": settings.strict_transport_security,
            "Content-Security-Policy": settings.content_security_policy,
            "Referrer-Policy": settings.referrer_policy,
            "Permissions-Policy": settings.permissions_policy,
            "Cache-Control": settings.cache_control,
        }

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for name, value in self._headers.items():
            response.headers[name] = value
        return response
