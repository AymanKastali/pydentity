from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from ulid import ULID

from pydentity.adapters.inbound.api.context import client_ip_var, trace_id_var

if TYPE_CHECKING:
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import Response


class TraceMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        trace_id = str(ULID())
        trace_id_var.set(trace_id)
        client_ip_var.set(request.client.host if request.client else "")
        response = await call_next(request)
        response.headers["X-Trace-Id"] = trace_id
        return response
