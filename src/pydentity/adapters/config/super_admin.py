from __future__ import annotations

from pydantic import SecretStr  # noqa: TC002
from pydantic_settings import BaseSettings


class SuperAdminSettings(BaseSettings):
    email: str
    password: SecretStr
