from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

# --- Identity VOs ---


@dataclass(frozen=True, slots=True)
class UserId:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("UserId cannot be empty")


@dataclass(frozen=True, slots=True)
class SessionId:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("SessionId cannot be empty")


@dataclass(frozen=True, slots=True)
class RoleId:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("RoleId cannot be empty")


# --- Authorization VOs ---


@dataclass(frozen=True, slots=True)
class Permission:
    resource: str
    action: str

    def __post_init__(self) -> None:
        if not self.resource:
            raise ValueError("Permission resource cannot be empty")
        if not self.action:
            raise ValueError("Permission action cannot be empty")


# --- Auth VOs ---

_EMAIL_LOCAL_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_EMAIL_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


@dataclass(frozen=True, slots=True)
class EmailAddress:
    local_part: str
    domain: str

    def __post_init__(self) -> None:
        if not self.local_part or not _EMAIL_LOCAL_RE.match(self.local_part):
            raise ValueError(f"Invalid email local part: {self.local_part!r}")
        if not self.domain or not _EMAIL_DOMAIN_RE.match(self.domain):
            raise ValueError(f"Invalid email domain: {self.domain!r}")
        if len(self.local_part) > 64:
            raise ValueError("Email local part exceeds 64 characters")
        if len(self.domain) > 255:
            raise ValueError("Email domain exceeds 255 characters")

    @property
    def full_address(self) -> str:
        return f"{self.local_part}@{self.domain}"

    def __str__(self) -> str:
        return self.full_address


@dataclass(frozen=True, slots=True)
class HashedPassword:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("HashedPassword cannot be empty")


@dataclass(frozen=True, slots=True)
class HashedRefreshToken:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("HashedRefreshToken cannot be empty")


@dataclass(frozen=True, slots=True)
class RefreshTokenFamily:
    family_id: str
    generation: int

    def __post_init__(self) -> None:
        if not self.family_id:
            raise ValueError("RefreshTokenFamily family_id cannot be empty")
        if self.generation < 0:
            raise ValueError("RefreshTokenFamily generation must be non-negative")

    def next_generation(self) -> RefreshTokenFamily:
        return RefreshTokenFamily(
            family_id=self.family_id,
            generation=self.generation + 1,
        )


@dataclass(frozen=True, slots=True)
class EmailVerificationToken:
    token_hash: str
    expires_at: datetime

    def __post_init__(self) -> None:
        if not self.token_hash:
            raise ValueError("EmailVerificationToken token_hash cannot be empty")

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def matches(self, raw_token_hash: str) -> bool:
        return self.token_hash == raw_token_hash


@dataclass(frozen=True, slots=True)
class PasswordResetToken:
    token_hash: str
    expires_at: datetime

    def __post_init__(self) -> None:
        if not self.token_hash:
            raise ValueError("PasswordResetToken token_hash cannot be empty")

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def matches(self, raw_token_hash: str) -> bool:
        return self.token_hash == raw_token_hash


# --- Token VO ---


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    issuer: str
    subject: UserId
    session_id: SessionId
    issued_at: datetime
    expires_at: datetime
    jti: str
    permissions: frozenset[Permission]

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("AccessTokenClaims issuer cannot be empty")
        if not self.jti:
            raise ValueError("AccessTokenClaims jti cannot be empty")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
