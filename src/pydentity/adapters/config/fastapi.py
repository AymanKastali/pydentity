from typing import TYPE_CHECKING

from pydentity.adapters.config.base import BaseSettings

if TYPE_CHECKING:
    from pydantic import HttpUrl


class FastAPISettings(BaseSettings):
    app_name: str
    app_version: str
    host: HttpUrl
    port: int
    reload: bool
    log_level: str
