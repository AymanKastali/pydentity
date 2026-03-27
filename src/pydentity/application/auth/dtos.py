from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthenticateDTO:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class RefreshDTO:
    refresh_token: str


@dataclass(frozen=True, slots=True)
class LogoutDTO:
    refresh_token: str


@dataclass(frozen=True, slots=True)
class TokenPairDTO:
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
