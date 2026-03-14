"""add index on sessions.refresh_token_hash

Revision ID: a9f3c2d1e4b7
Revises: 431ac8167e43
Create Date: 2026-03-14 18:00:00.000000

"""
from typing import TYPE_CHECKING

from alembic import op

if TYPE_CHECKING:
    from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "a9f3c2d1e4b7"
down_revision: str | None = "431ac8167e43"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_sessions_refresh_token_hash",
        "sessions",
        ["refresh_token_hash"],
    )


def downgrade() -> None:
    op.drop_index("ix_sessions_refresh_token_hash", table_name="sessions")
