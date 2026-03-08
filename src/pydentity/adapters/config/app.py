from functools import lru_cache

from pydantic import Field

from pydentity.adapters.config.base import BaseSettings
from pydentity.adapters.config.fastapi import FastAPISettings  # noqa: TC001
from pydentity.adapters.config.postgres import PostgresSettings  # noqa: TC001
from pydentity.adapters.config.redis import RedisSettings  # noqa: TC001
from pydentity.adapters.config.security import SecuritySettings  # noqa: TC001
from pydentity.adapters.config.smtp import SmtpSettings  # noqa: TC001


class AppSettings(BaseSettings):
    fastapi: FastAPISettings = Field(default_factory=FastAPISettings)
    postgres: PostgresSettings
    security: SecuritySettings
    smtp: SmtpSettings = Field(default_factory=SmtpSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)


@lru_cache(maxsize=1)
def get_app_settings() -> AppSettings:
    return AppSettings()  # type: ignore
