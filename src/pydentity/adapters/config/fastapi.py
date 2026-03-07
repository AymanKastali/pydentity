from pydentity.adapters.config.base import BaseSettings


class FastAPISettings(BaseSettings):
    app_name: str
    app_version: str
    host: str
    port: int
    reload: bool
    log_level: str
