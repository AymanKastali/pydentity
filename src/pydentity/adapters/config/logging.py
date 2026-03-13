from pydentity.adapters.config.base import BaseSettings


class LoggingSettings(BaseSettings):
    json_format: bool = False
    level: str = "info"
