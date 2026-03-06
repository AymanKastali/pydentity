from typing import TYPE_CHECKING

from pydentity.adapters.config.base import BaseSettings

if TYPE_CHECKING:
    from pydantic import PostgresDsn


class PostgresSettings(BaseSettings):
    dsn: PostgresDsn
    pool_size: int = 5
    max_overflow: int = 10
    pool_recycle: int = 1800
    echo: bool = False
