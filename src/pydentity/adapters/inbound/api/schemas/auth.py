from __future__ import annotations

from pydantic import BaseModel


class RegisterRequest(BaseModel):
    email: str
    password: str


class RegisterResponse(BaseModel):
    email: str


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    user_id: str
    session_id: str
    device_id: str


class RefreshRequest(BaseModel):
    refresh_token: str
    session_id: str


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str


class LogoutRequest(BaseModel):
    session_id: str
