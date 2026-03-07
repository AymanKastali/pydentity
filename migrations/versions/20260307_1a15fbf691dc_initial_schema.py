"""initial_schema

Revision ID: 1a15fbf691dc
Revises:
Create Date: 2026-03-07 00:00:00.000000

"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1a15fbf691dc"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("domain_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False),
        sa.Column("permissions", sa.ARRAY(sa.String()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("domain_id", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("email_verification_is_verified", sa.Boolean(), nullable=False),
        sa.Column("email_verification_token_hash", sa.LargeBinary(), nullable=True),
        sa.Column(
            "email_verification_token_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("credentials_password_hash", sa.LargeBinary(), nullable=False),
        sa.Column(
            "credentials_password_reset_token_hash", sa.LargeBinary(), nullable=True
        ),
        sa.Column(
            "credentials_password_reset_token_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "credentials_password_history",
            sa.ARRAY(sa.LargeBinary()),
            nullable=False,
        ),
        sa.Column("login_tracking_failed_attempts", sa.Integer(), nullable=False),
        sa.Column(
            "login_tracking_lockout_expiry", sa.DateTime(timezone=True), nullable=True
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id"),
        sa.UniqueConstraint("email"),
    )
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("domain_id", sa.String(), nullable=False),
        sa.Column(
            "user_fk",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_domain_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("platform", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("is_trusted", sa.Boolean(), nullable=False),
        sa.Column("last_active", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id"),
        sa.UniqueConstraint("fingerprint"),
    )
    op.create_table(
        "user_roles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "user_fk",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "role_fk",
            sa.Integer(),
            sa.ForeignKey("roles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_fk", "role_fk", name="uq_user_role"),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("domain_id", sa.String(), nullable=False),
        sa.Column(
            "user_fk",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "device_fk",
            sa.Integer(),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_domain_id", sa.String(), nullable=False),
        sa.Column("device_domain_id", sa.String(), nullable=False),
        sa.Column("refresh_token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("refresh_token_family_id", sa.String(), nullable=False),
        sa.Column("refresh_token_family_generation", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("session_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_refresh", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expiry", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id"),
    )


def downgrade() -> None:
    op.drop_table("sessions")
    op.drop_table("user_roles")
    op.drop_table("devices")
    op.drop_table("users")
    op.drop_table("roles")
