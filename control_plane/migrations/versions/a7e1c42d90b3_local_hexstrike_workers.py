"""Track local Docker workers separately from production native runners.

Revision ID: a7e1c42d90b3
Revises: f6c7a8321d05
"""

from alembic import op
import sqlalchemy as sa

revision = "a7e1c42d90b3"
down_revision = "f6c7a8321d05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "local_hexstrike_workers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("local_hexstrike_workers")
