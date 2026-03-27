from datetime import datetime
from uuid import UUID

from sqlmodel import Field, SQLModel


class AccountModel(SQLModel, table=True):
    __tablename__ = "accounts"

    id: UUID = Field(primary_key=True)
    email: str = Field(max_length=254, unique=True, nullable=False)
    hashed_password: str = Field(nullable=False)
    status: str = Field(
        max_length=32,
        nullable=False,
        default="pending_verification",
    )
    verification_token: str | None = Field(max_length=128, default=None, nullable=True)
    verified_at: datetime | None = Field(default=None, nullable=True)
    created_at: datetime = Field(nullable=False)
    updated_at: datetime = Field(nullable=False)


class RefreshTokenModel(SQLModel, table=True):
    __tablename__ = "refresh_tokens"

    id: UUID = Field(primary_key=True)
    token_hash: str = Field(max_length=64, unique=True, nullable=False)
    account_id: UUID = Field(nullable=False, foreign_key="accounts.id")
    family: UUID = Field(nullable=False, index=True)
    expires_at: datetime = Field(nullable=False)
    revoked_at: datetime | None = Field(default=None, nullable=True)
    created_at: datetime = Field(nullable=False)
