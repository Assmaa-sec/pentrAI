"""persist the user-visible scan scope note

Revision ID: 0d4e17b3f2c1
Revises: 229e5e7261f9
"""

from alembic import op
import sqlalchemy as sa

revision = "0d4e17b3f2c1"
down_revision = "229e5e7261f9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("scope_note", sa.String(length=2000),
                                   server_default="", nullable=False))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("scope_note")
