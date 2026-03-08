from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    email: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    user_id: str
    session_id: str
    device_id: str


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=512)
    session_id: str = Field(min_length=1, max_length=255)


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str


class LogoutRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=255)
