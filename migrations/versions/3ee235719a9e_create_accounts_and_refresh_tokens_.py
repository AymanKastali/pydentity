"""create accounts and refresh_tokens tables

Revision ID: 3ee235719a9e
Revises:
Create Date: 2026-03-27 12:35:40.867244

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "3ee235719a9e"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "email",
            sa.String(254),
            unique=True,
            nullable=False,
        ),
        sa.Column("hashed_password", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default="pending_verification",
        ),
        sa.Column("verification_token", sa.String(128), nullable=True),
        sa.Column(
            "verified_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.create_index("ix_accounts_email", "accounts", ["email"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "token_hash",
            sa.String(64),
            unique=True,
            nullable=False,
        ),
        sa.Column(
            "account_id",
            sa.Uuid(),
            sa.ForeignKey("accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("family", sa.Uuid(), nullable=False),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_refresh_tokens_token_hash",
        "refresh_tokens",
        ["token_hash"],
    )
    op.create_index(
        "ix_refresh_tokens_account_id",
        "refresh_tokens",
        ["account_id"],
    )
    op.create_index(
        "ix_refresh_tokens_family",
        "refresh_tokens",
        ["family"],
    )


def downgrade() -> None:
    op.drop_table("refresh_tokens")
    op.drop_table("accounts")
