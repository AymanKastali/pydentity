from __future__ import annotations

import hashlib
import secrets
from typing import TYPE_CHECKING

from pydentity.domain.models.value_objects import (
    EmailVerificationToken,
    HashedResetToken,
    HashedVerificationToken,
    PasswordResetToken,
)
from pydentity.domain.ports.raw_token_generator import RawTokenGeneratorPort
from pydentity.domain.ports.reset_token_generator import ResetTokenGeneratorPort
from pydentity.domain.ports.verification_token_generator import (
    VerificationTokenGeneratorPort,
)

if TYPE_CHECKING:
    from datetime import datetime, timedelta

_TOKEN_BYTES = 32


class SecretsRawTokenGenerator(RawTokenGeneratorPort):
    def generate(self) -> str:
        return secrets.token_urlsafe(_TOKEN_BYTES)


class HashedVerificationTokenGenerator(VerificationTokenGeneratorPort):
    def generate(
        self, ttl: timedelta, now: datetime
    ) -> tuple[str, EmailVerificationToken]:
        raw = secrets.token_urlsafe(_TOKEN_BYTES)
        hashed = HashedVerificationToken(value=hashlib.sha256(raw.encode()).digest())
        token = EmailVerificationToken(token_hash=hashed, expires_at=now + ttl)
        return raw, token


class HashedResetTokenGenerator(ResetTokenGeneratorPort):
    def generate(self, ttl: timedelta, now: datetime) -> tuple[str, PasswordResetToken]:
        raw = secrets.token_urlsafe(_TOKEN_BYTES)
        hashed = HashedResetToken(value=hashlib.sha256(raw.encode()).digest())
        token = PasswordResetToken(token_hash=hashed, expires_at=now + ttl)
        return raw, token
