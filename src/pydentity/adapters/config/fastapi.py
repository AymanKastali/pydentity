from pydantic import computed_field

from pydentity.adapters.config.base import BaseSettings


class FastAPISettings(BaseSettings):
    app_name: str = "pydentity"
    app_version: str = "0.1.0"
    host: str = "0.0.0.0"
    port: int = 8000
    is_production: bool = True
    log_level: str = "info"
    log_format: str = "rich"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reload(self) -> bool:
        return not self.is_production
