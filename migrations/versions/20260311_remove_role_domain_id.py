"""remove role domain_id

Revision ID: a3b7c9d1e2f4
Revises: 0f51e1b3e658
Create Date: 2026-03-11 00:00:00.000000

"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3b7c9d1e2f4"
down_revision: str | None = "0f51e1b3e658"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("roles_domain_id_key", "roles", type_="unique")
    op.drop_column("roles", "domain_id")


def downgrade() -> None:
    op.add_column(
        "roles",
        sa.Column("domain_id", sa.String(), nullable=True),
    )
    # Backfill domain_id with the role name (unique natural key)
    op.execute("UPDATE roles SET domain_id = name")
    op.alter_column("roles", "domain_id", nullable=False)
    op.create_unique_constraint("roles_domain_id_key", "roles", ["domain_id"])
