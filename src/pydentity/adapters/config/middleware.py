from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TrustedHostSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PYDENTITY_MIDDLEWARE__TRUSTED_HOST__")

    allowed_hosts: list[str] = Field(default=["*"])


class CorsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PYDENTITY_MIDDLEWARE__CORS__")

    allowed_origins: list[str] = Field(default=["*"])
    allowed_methods: list[str] = Field(default=["*"])
    allowed_headers: list[str] = Field(
        default=[
            "Authorization",
            "Content-Type",
            "X-Device-Id",
            "X-Device-Name",
            "X-Device-Type",
        ],
    )
    allow_credentials: bool = True
    max_age: int = 600


class SecurityHeadersSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PYDENTITY_MIDDLEWARE__SECURITY_HEADERS__",
    )

    x_content_type_options: str = "nosniff"
    x_frame_options: str = "DENY"
    strict_transport_security: str = "max-age=63072000; includeSubDomains; preload"
    content_security_policy: str = "default-src 'none'; frame-ancestors 'none'"
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: str = "camera=(), microphone=(), geolocation=(), payment=()"
    cache_control: str = "no-store"


class RateLimitSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PYDENTITY_MIDDLEWARE__RATE_LIMIT__")

    enabled: bool = True
    general_limit: int = 100
    general_window_seconds: int = 60
    auth_limit: int = 10
    auth_window_seconds: int = 60
    auth_paths: list[str] = Field(
        default=[
            "/auth/login",
            "/auth/register",
            "/password/reset-request",
            "/password/reset",
        ],
    )


class RequestLoggingSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PYDENTITY_MIDDLEWARE__REQUEST_LOGGING__",
    )

    excluded_paths: list[str] = Field(
        default=["/docs", "/redoc", "/openapi.json", "/health"],
    )


class MiddlewareSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PYDENTITY_MIDDLEWARE__")

    trusted_host: TrustedHostSettings = Field(
        default_factory=TrustedHostSettings,
    )
    cors: CorsSettings = Field(default_factory=CorsSettings)
    security_headers: SecurityHeadersSettings = Field(
        default_factory=SecurityHeadersSettings,
    )
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    request_logging: RequestLoggingSettings = Field(
        default_factory=RequestLoggingSettings,
    )
