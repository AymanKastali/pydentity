from pydantic import PostgresDsn  # noqa: TC002

from pydentity.adapters.config.base import BaseSettings


class PostgresSettings(BaseSettings):
    dsn: PostgresDsn
    pool_size: int = 20
    max_overflow: int = 30
    pool_recycle: int = 1800
    echo: bool = False
