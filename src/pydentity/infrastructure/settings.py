from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "PYDENTITY_"}

    database_url: str = (
        "postgresql+asyncpg://pydentity:pydentity@localhost:5432/pydentity"
    )
    jwt_private_key_path: str = "keys/"
    jwt_access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4
    app_host: str = "0.0.0.0"
    app_port: int = 8000
