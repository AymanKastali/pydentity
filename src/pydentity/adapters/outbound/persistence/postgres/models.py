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
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(
        default_factory=_now,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=_now,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False),
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


# ── UserModel ─────────────────────────────────────────────────────────────────


class UserModel(BaseModel, table=True):
    __tablename__: ClassVar[str] = "users"

    domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))
    email: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))
    status: str = Field(sa_column=sa.Column(sa.String, nullable=False))

    # EmailVerification
    email_verification_is_verified: bool = Field(
        sa_column=sa.Column(sa.Boolean, nullable=False, default=False)
    )
    email_verification_token_hash: bytes | None = Field(
        default=None,
        sa_column=sa.Column(sa.LargeBinary, nullable=True),
    )
    email_verification_token_expires_at: datetime | None = Field(
        default=None,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=True),
    )

    # Credentials
    credentials_password_hash: bytes = Field(
        sa_column=sa.Column(sa.LargeBinary, nullable=False)
    )
    credentials_password_reset_token_hash: bytes | None = Field(
        default=None,
        sa_column=sa.Column(sa.LargeBinary, nullable=True),
    )
    credentials_password_reset_token_expires_at: datetime | None = Field(
        default=None,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=True),
    )
    credentials_password_history: list[bytes] = Field(
        default_factory=list,
        sa_column=sa.Column(sa.ARRAY(sa.LargeBinary), nullable=False),
    )

    # LoginTracking
    login_tracking_failed_attempts: int = Field(
        sa_column=sa.Column(sa.Integer, nullable=False, default=0)
    )
    login_tracking_lockout_expiry: datetime | None = Field(
        default=None,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=True),
    )

    # relationships
    roles: list[RoleModel] = Relationship(
        back_populates="users", link_model=UserRoleLink
    )
    sessions: list[SessionModel] = Relationship(back_populates="user")
    devices: list[DeviceModel] = Relationship(back_populates="user")


# ── RoleModel ─────────────────────────────────────────────────────────────────


class RoleModel(BaseModel, table=True):
    __tablename__: ClassVar[str] = "roles"

    domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))
    name: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))
    description: str = Field(sa_column=sa.Column(sa.String, nullable=False))
    permissions: list[str] = Field(
        default_factory=list,
        sa_column=sa.Column(sa.ARRAY(sa.String), nullable=False),
    )

    # relationships
    users: list[UserModel] = Relationship(
        back_populates="roles", link_model=UserRoleLink
    )


# ── SessionModel ──────────────────────────────────────────────────────────────


class SessionModel(BaseModel, table=True):
    __tablename__: ClassVar[str] = "sessions"

    domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))
    user_fk: int = Field(
        sa_column=sa.Column(
            sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        )
    )
    device_fk: int = Field(
        sa_column=sa.Column(
            sa.Integer, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
        )
    )
    user_domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False))
    device_domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False))
    refresh_token_hash: bytes = Field(
        sa_column=sa.Column(sa.LargeBinary, nullable=False)
    )
    refresh_token_family_id: str = Field(sa_column=sa.Column(sa.String, nullable=False))
    refresh_token_family_generation: int = Field(
        sa_column=sa.Column(sa.Integer, nullable=False)
    )
    status: str = Field(sa_column=sa.Column(sa.String, nullable=False))
    session_created_at: datetime = Field(
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False)
    )
    last_refresh: datetime = Field(
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False)
    )
    expiry: datetime = Field(
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False)
    )

    # relationships
    user: UserModel = Relationship(back_populates="sessions")
    device: DeviceModel = Relationship(back_populates="sessions")


# ── DeviceModel ───────────────────────────────────────────────────────────────


class DeviceModel(BaseModel, table=True):
    __tablename__: ClassVar[str] = "devices"

    domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False, unique=True))
    user_fk: int = Field(
        sa_column=sa.Column(
            sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        )
    )
    user_domain_id: str = Field(sa_column=sa.Column(sa.String, nullable=False))
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
