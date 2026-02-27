from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydentity.domain.exceptions import EmptyValueError, InvalidValueError

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.value_objects import Permission, SessionId, UserId


@dataclass(frozen=True, slots=True)
class RegisterUserInput:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class RegisterUserOutput:
    user_id: str
    email: str


@dataclass(frozen=True, slots=True)
class AuthenticateUserInput:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class AuthenticateUserOutput:
    access_token: str
    refresh_token: str
    user_id: str
    session_id: str


@dataclass(frozen=True, slots=True)
class RefreshAccessTokenInput:
    refresh_token: str
    session_id: str


@dataclass(frozen=True, slots=True)
class RefreshAccessTokenOutput:
    access_token: str
    refresh_token: str


@dataclass(frozen=True, slots=True)
class LogoutUserInput:
    session_id: str


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    issuer: str
    subject: UserId
    session_id: SessionId
    issued_at: datetime
    expires_at: datetime
    token_id: str
    permissions: frozenset[Permission]

    def __post_init__(self) -> None:
        if not self.issuer:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.issuer")
        if not self.token_id:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.token_id")
        if self.expires_at <= self.issued_at:
            raise InvalidValueError(
                field_name=f"{self.__class__.__name__}.expires_at",
                reason="must be after issued_at",
            )
