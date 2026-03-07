from datetime import UTC, datetime
from typing import ClassVar

from sqlalchemy import DateTime
from sqlmodel import (
    ARRAY,
    Column,
    Field,
    LargeBinary,
    Relationship,
    SQLModel,
    String,
    UniqueConstraint,
)

# ── helpers ───────────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC)


# ── join tables ───────────────────────────────────────────────────────────────


class UserRoleLink(SQLModel, table=True):
    __tablename__: ClassVar[str] = "user_roles"

    user_fk: int = Field(foreign_key="users.id", primary_key=True)
    role_fk: int = Field(foreign_key="roles.id", primary_key=True)

    __table_args__: ClassVar[tuple[UniqueConstraint, ...]] = (
        UniqueConstraint("user_fk", "role_fk", name="uq_user_role"),
    )


# ── UserModel ─────────────────────────────────────────────────────────────────


class UserModel(SQLModel, table=True):
    __tablename__: ClassVar[str] = "users"

    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now)
    )
    updated_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now)
    )
    deleted_at: datetime | None = Field(
        sa_column=Column(DateTime(timezone=True), nullable=True)
    )

    domain_id: str = Field(unique=True, nullable=False)
    email: str = Field(unique=True, nullable=False)
    status: str = Field(nullable=False)

    # EmailVerification
    email_verification_is_verified: bool = Field(default=False, nullable=False)
    email_verification_token_hash: bytes | None = Field(
        default=None, sa_type=LargeBinary
    )
    email_verification_token_expires_at: datetime | None = Field(
        sa_column=Column(DateTime(timezone=True), nullable=True, default=None)
    )

    # Credentials
    credentials_password_hash: bytes = Field(sa_type=LargeBinary, nullable=False)
    credentials_password_reset_token_hash: bytes | None = Field(
        default=None, sa_type=LargeBinary
    )
    credentials_password_reset_token_expires_at: datetime | None = Field(
        sa_column=Column(DateTime(timezone=True), nullable=True, default=None)
    )
    credentials_password_history: list[bytes] = Field(
        default_factory=list, sa_column=Column(ARRAY(LargeBinary), nullable=False)
    )

    # LoginTracking
    login_tracking_failed_attempts: int = Field(default=0, nullable=False)
    login_tracking_lockout_expiry: datetime | None = Field(
        sa_column=Column(DateTime(timezone=True), nullable=True, default=None)
    )

    # relationships
    roles: list[RoleModel] = Relationship(
        back_populates="users", link_model=UserRoleLink
    )
    sessions: list[SessionModel] = Relationship(back_populates="user")
    devices: list[DeviceModel] = Relationship(back_populates="user")


# ── RoleModel ─────────────────────────────────────────────────────────────────


class RoleModel(SQLModel, table=True):
    __tablename__: ClassVar[str] = "roles"

    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now)
    )
    updated_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now)
    )
    deleted_at: datetime | None = Field(
        sa_column=Column(DateTime(timezone=True), nullable=True)
    )

    domain_id: str = Field(unique=True, nullable=False)
    name: str = Field(unique=True, nullable=False)
    description: str = Field(nullable=False)
    permissions: list[str] = Field(
        default_factory=list, sa_column=Column(ARRAY(String), nullable=False)
    )

    # relationships
    users: list[UserModel] = Relationship(
        back_populates="roles", link_model=UserRoleLink
    )


# ── SessionModel ──────────────────────────────────────────────────────────────


class SessionModel(SQLModel, table=True):
    __tablename__: ClassVar[str] = "sessions"

    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now)
    )
    updated_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now)
    )
    deleted_at: datetime | None = Field(
        sa_column=Column(DateTime(timezone=True), nullable=True)
    )

    domain_id: str = Field(unique=True, nullable=False)
    user_fk: int = Field(foreign_key="users.id", nullable=False)
    device_fk: int = Field(foreign_key="devices.id", nullable=False)
    user_domain_id: str = Field(nullable=False)
    device_domain_id: str = Field(nullable=False)
    refresh_token_hash: bytes = Field(sa_type=LargeBinary, nullable=False)
    refresh_token_family_id: str = Field(nullable=False)
    refresh_token_family_generation: int = Field(nullable=False)
    status: str = Field(nullable=False)
    session_created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    last_refresh: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    expiry: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))

    # relationships
    user: UserModel = Relationship(back_populates="sessions")
    device: DeviceModel = Relationship(back_populates="sessions")


# ── DeviceModel ───────────────────────────────────────────────────────────────


class DeviceModel(SQLModel, table=True):
    __tablename__: ClassVar[str] = "devices"

    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now)
    )
    updated_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now)
    )
    deleted_at: datetime | None = Field(
        sa_column=Column(DateTime(timezone=True), nullable=True)
    )

    domain_id: str = Field(unique=True, nullable=False)
    user_fk: int = Field(foreign_key="users.id", nullable=False)
    user_domain_id: str = Field(nullable=False)
    name: str = Field(nullable=False)
    fingerprint: str = Field(unique=True, nullable=False)
    platform: str = Field(nullable=False)
    status: str = Field(nullable=False)
    is_trusted: bool = Field(default=False, nullable=False)
    last_active: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )

    # relationships
    user: UserModel = Relationship(back_populates="devices")
    sessions: list[SessionModel] = Relationship(back_populates="device")
