"""server_generated_device_id

Revision ID: 431ac8167e43
Revises: bbfd7c09ee6f
Create Date: 2026-03-14 15:31:58.964199

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "431ac8167e43"
down_revision: Union[str, None] = "bbfd7c09ee6f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(op.f("devices_domain_id_key"), "devices", type_="unique")
    op.create_index("ix_devices_domain_id", "devices", ["domain_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_devices_domain_id", table_name="devices")
    op.create_unique_constraint(
        op.f("devices_domain_id_key"),
        "devices",
        ["domain_id"],
    )
