from pydentity.adapters.config.base import BaseSettings


class SmtpSettings(BaseSettings):
    host: str = "localhost"
    port: int = 1025
