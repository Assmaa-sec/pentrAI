"""Track live native runner workers for admission readiness.

Revision ID: f6c7a8321d05
Revises: e5c6490b7a32
"""

from alembic import op
import sqlalchemy as sa

revision = "f6c7a8321d05"
down_revision = "e5c6490b7a32"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_runner_workers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ready", sa.Boolean(), nullable=False),
        sa.Column("url_ready", sa.Boolean(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("native_runner_workers")
