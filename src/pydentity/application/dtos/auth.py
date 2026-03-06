from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RegisterUserInput:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class RegisterUserOutput:
    email: str


@dataclass(frozen=True, slots=True)
class AuthenticateUserInput:
    email: str
    password: str
    device_id: str
    device_name: str
    raw_fingerprint: str
    platform: str


@dataclass(frozen=True, slots=True)
class AuthenticateUserOutput:
    access_token: str
    refresh_token: str
    user_id: str
    session_id: str
    device_id: str


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
