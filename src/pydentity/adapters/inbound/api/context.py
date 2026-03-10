from __future__ import annotations

from contextvars import ContextVar

trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")
client_ip_var: ContextVar[str] = ContextVar("client_ip", default="")
