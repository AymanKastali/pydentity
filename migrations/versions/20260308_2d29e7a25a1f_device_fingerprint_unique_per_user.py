"""device fingerprint unique per user

Revision ID: 2d29e7a25a1f
Revises: 189ae4c62f01
Create Date: 2026-03-08 10:48:12.493460

"""

from collections.abc import Sequence  # noqa: TC003

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2d29e7a25a1f"
down_revision: str | None = "189ae4c62f01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("devices_fingerprint_key", "devices", type_="unique")
    op.create_unique_constraint(
        "uq_devices_user_fingerprint", "devices", ["user_fk", "fingerprint"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_devices_user_fingerprint", "devices", type_="unique")
    op.create_unique_constraint("devices_fingerprint_key", "devices", ["fingerprint"])
