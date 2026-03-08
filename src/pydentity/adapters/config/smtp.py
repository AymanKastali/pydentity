from pydantic import SecretStr  # noqa: TC002

from pydentity.adapters.config.base import BaseSettings


class SmtpSettings(BaseSettings):
    host: str = "localhost"
    port: int = 1025
    username: str | None = None
    password: SecretStr | None = None
    use_tls: bool = False
    use_starttls: bool = False
    sender: str = "noreply@localhost"
    sender_name: str = "Pydentity"
