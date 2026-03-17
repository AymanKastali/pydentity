from datetime import timedelta
from pathlib import Path  # noqa: TC003

from pydentity.adapters.config.base import BaseSettings
from pydentity.domain.models.value_objects import (
    AccountLockoutPolicy,
    DevicePolicy,
    EmailVerificationPolicy,
    PasswordPolicy,
    TokenLifetimePolicy,
)


class SecuritySettings(BaseSettings):
    jwt_key_directory: Path
    token_issuer: str = "pydentity"
    token_audiences: list[str] = ["pydentity"]

    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = False
    password_history_size: int = 3

    lockout_max_attempts: int = 5
    lockout_duration_minutes: int = 15

    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 604800
    session_absolute_ttl_seconds: int = 2592000

    email_verification_on_register_required: bool = True
    email_verification_on_change_required: bool = True
    email_verification_ttl_hours: int = 24

    reset_token_ttl_hours: int = 1

    max_devices_per_user: int = 3

    @property
    def password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(
            min_length=self.password_min_length,
            require_uppercase=self.password_require_uppercase,
            require_lowercase=self.password_require_lowercase,
            require_digit=self.password_require_digit,
            require_special=self.password_require_special,
            history_size=self.password_history_size,
        )

    @property
    def lockout_policy(self) -> AccountLockoutPolicy:
        return AccountLockoutPolicy(
            max_attempts=self.lockout_max_attempts,
            lockout_duration=timedelta(minutes=self.lockout_duration_minutes),
        )

    @property
    def token_lifetime_policy(self) -> TokenLifetimePolicy:
        return TokenLifetimePolicy(
            access_token_ttl=timedelta(seconds=self.access_token_ttl_seconds),
            refresh_token_ttl=timedelta(seconds=self.refresh_token_ttl_seconds),
            session_absolute_ttl=timedelta(seconds=self.session_absolute_ttl_seconds),
        )

    @property
    def email_verification_policy(self) -> EmailVerificationPolicy:
        return EmailVerificationPolicy(
            required_on_registration=self.email_verification_on_register_required,
            required_on_email_change=self.email_verification_on_change_required,
            token_ttl=timedelta(hours=self.email_verification_ttl_hours),
        )

    @property
    def device_policy(self) -> DevicePolicy:
        return DevicePolicy(max_devices_per_user=self.max_devices_per_user)

    @property
    def reset_token_ttl(self) -> timedelta:
        return timedelta(hours=self.reset_token_ttl_hours)
