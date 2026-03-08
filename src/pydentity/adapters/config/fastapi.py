from pydentity.adapters.config.base import BaseSettings


class FastAPISettings(BaseSettings):
    app_name: str = "pydentity"
    app_version: str = "0.1.0"
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False
    log_level: str = "info"
