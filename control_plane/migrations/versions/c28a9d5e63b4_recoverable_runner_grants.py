"""Record signed-grant issue second for crash-safe runner dispatch.

Revision ID: c28a9d5e63b4
Revises: 821fb034ca12
"""

from alembic import op
import sqlalchemy as sa

revision = "c28a9d5e63b4"
down_revision = "821fb034ca12"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scan_grants") as batch:
        batch.add_column(sa.Column("issued_at", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scan_grants") as batch:
        batch.drop_column("issued_at")
