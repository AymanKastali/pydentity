from functools import lru_cache
from typing import TYPE_CHECKING

from pydentity.adapters.config.base import BaseSettings

if TYPE_CHECKING:
    from pydentity.adapters.config.fastapi import FastAPISettings
    from pydentity.adapters.config.postgres import PostgresSettings


class AppSettings(BaseSettings):
    fastapi: FastAPISettings
    postgres: PostgresSettings


@lru_cache(maxsize=1)
def get_app_settings() -> AppSettings:
    return AppSettings()  # type: ignore
