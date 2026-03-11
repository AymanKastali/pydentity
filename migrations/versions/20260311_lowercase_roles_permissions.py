"""lowercase roles and permissions

Revision ID: b4c8d2e3f5a6
Revises: a3b7c9d1e2f4
Create Date: 2026-03-11 00:00:00.000000

"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b4c8d2e3f5a6"
down_revision: str | None = "a3b7c9d1e2f4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("UPDATE roles SET name = LOWER(name)")
    op.execute(
        "UPDATE roles SET permissions = "
        "(SELECT array_agg(LOWER(p)) FROM unnest(permissions) AS p)"
    )


def downgrade() -> None:
    op.execute("UPDATE roles SET name = UPPER(name)")
    op.execute(
        "UPDATE roles SET permissions = "
        "(SELECT array_agg(UPPER(p)) FROM unnest(permissions) AS p)"
    )
