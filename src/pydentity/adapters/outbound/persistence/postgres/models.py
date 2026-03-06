from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

import sqlalchemy as sa
from sqlmodel import Field, Relationship, SQLModel

# ── helpers ───────────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC)


# ── base record (GORM-style) ──────────────────────────────────────────────────


class BaseModel(SQLModel):
    id: int | None = Field(
        default=None,
        sa_column=sa.Column(sa.Integer, primary_key=True, autoincrement=True),
    )
    created_at: datetime = Field(
        default_factory=_now,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False, default=_now),
    )
    updated_at: datetime = Field(
        default_factory=_now,
        sa_column=sa.Column(
            sa.DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
        ),
    )
    deleted_at: datetime | None = Field(
        default=None,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=True),
    )


# ── join tables ───────────────────────────────────────────────────────────────


class UserRoleLink(BaseModel, table=True):
    __tablename__: ClassVar[str] = "user_roles"

    user_fk: int = Field(
        sa_column=sa.Column(
            sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        )
    )
    role_fk: int = Field(
        sa_column=sa.Column(
            sa.Integer, sa.ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
        )
    )

    __table_args__: ClassVar[tuple[sa.UniqueConstraint, ...]] = (
        sa.UniqueConstraint("user_fk", "role_fk", name="uq_user_role"),
    )


# ── tables ────────────────────────────────────────────────────────────────────


# ── UserModel ─────────────────────────────────────────────────────────────────
class UserModel(BaseModel, table=True):
    __tablename__: ClassVar[str] = "users"

    domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))
    email: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))
    status: str = Field(sa_column=sa.Column(sa.String, nullable=False))

    # Fix: Renamed fields to match mapper (added _hash and _expires_at)
    email_verification_is_verified: bool = Field(default=False)
    email_verification_token_hash: str | None = Field(default=None)
    email_verification_token_expires_at: datetime | None = Field(default=None)

    credentials_password_hash: str = Field(nullable=False)
    # Fix: Renamed fields to match mapper
    credentials_password_reset_token_hash: str | None = Field(default=None)
    credentials_password_reset_token_expires_at: datetime | None = Field(default=None)

    credentials_password_history: list[str] = Field(
        default_factory=list, sa_column=sa.Column(sa.JSON, nullable=False)
    )

    login_tracking_failed_attempts: int = Field(default=0)
    login_tracking_lockout_expiry: datetime | None = Field(default=None)

    roles: list[RoleModel] = Relationship(
        back_populates="users", link_model=UserRoleLink
    )
    sessions: list[SessionModel] = Relationship(back_populates="user")
    devices: list[DeviceModel] = Relationship(back_populates="user")


# ── RoleModel ─────────────────────────────────────────────────────────────────
class RoleModel(BaseModel, table=True):
    __tablename__: ClassVar[str] = "roles"

    # domain identity
    domain_id: str = Field(
        sa_column=sa.Column(sa.String, nullable=False, unique=True),
    )

    # RoleName
    name: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))

    # RoleDescription
    description: str = Field(sa_column=sa.Column(sa.String, nullable=False))

    # permissions stored as JSON array of strings
    permissions: list[str] = Field(
        default_factory=list,
        sa_column=sa.Column(sa.JSON, nullable=False, default=list),
    )

    # relationships
    users: list[UserModel] = Relationship(
        back_populates="roles", link_model=UserRoleLink
    )


# ── SessionModel ─────────────────────────────────────────────────────────────────
class SessionModel(BaseModel, table=True):
    __tablename__: ClassVar[str] = "sessions"

    domain_id: str = Field(nullable=False, unique=True)
    user_fk: int = Field(foreign_key="users.id", ondelete="CASCADE")
    device_fk: int = Field(foreign_key="devices.id", ondelete="CASCADE")

    # Fix: Using String for domain IDs to be consistent with User/Device domain_id
    user_domain_id: str = Field(nullable=False)
    device_domain_id: str = Field(nullable=False)

    refresh_token_hash: str = Field(nullable=False)

    # Fix: Expanded RefreshTokenFamily to match the mapper's flattened fields
    refresh_token_family_id: str = Field(nullable=False)
    refresh_token_family_generation: int = Field(nullable=False)

    status: str = Field(nullable=False)
    session_created_at: datetime = Field(nullable=False)
    last_refresh: datetime = Field(nullable=False)
    expiry: datetime = Field(nullable=False)

    user: UserModel = Relationship(back_populates="sessions")
    device: DeviceModel = Relationship(back_populates="sessions")


# ── DeviceModel ─────────────────────────────────────────────────────────────────
class DeviceModel(BaseModel, table=True):
    __tablename__: ClassVar[str] = "devices"

    # domain identity
    domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))

    # foreign key
    user_fk: int = Field(
        sa_column=sa.Column(
            sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        )
    )

    # domain fields
    user_domain_id: str = Field(
        sa_column=sa.Column(sa.String, nullable=False, unique=True)
    )
    name: str = Field(sa_column=sa.Column(sa.String, nullable=False))
    fingerprint: str = Field(
        sa_column=sa.Column(sa.String, nullable=False, unique=True)
    )
    platform: str = Field(sa_column=sa.Column(sa.String, nullable=False))
    status: str = Field(sa_column=sa.Column(sa.String, nullable=False))
    is_trusted: bool = Field(
        sa_column=sa.Column(sa.Boolean, nullable=False, default=False)
    )
    last_active: datetime = Field(
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False)
    )

    # relationships
    user: UserModel = Relationship(back_populates="devices")
    sessions: list[SessionModel] = Relationship(back_populates="device")
