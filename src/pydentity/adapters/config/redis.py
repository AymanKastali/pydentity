from pydentity.adapters.config.base import BaseSettings


class RedisSettings(BaseSettings):
    url: str = "redis://localhost:6379/0"
    event_channel: str = "pydentity:domain_events"
