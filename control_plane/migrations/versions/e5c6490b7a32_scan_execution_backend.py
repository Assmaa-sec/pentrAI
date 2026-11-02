"""Bind each scan to one execution backend.

Revision ID: e5c6490b7a32
Revises: d4f7c38a09b2
"""

from alembic import op
import sqlalchemy as sa

revision = "e5c6490b7a32"
down_revision = "d4f7c38a09b2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing source scans belong to the prior local worker; existing URL
    # scans already targeted native HexStrike and must retain that route.
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("execution_backend", sa.String(20), nullable=False,
                                   server_default="local_static"))
    op.execute("UPDATE scans SET execution_backend = 'hexstrike' WHERE target_url IS NOT NULL")
    with op.batch_alter_table("scans") as batch:
        batch.alter_column("execution_backend", server_default="hexstrike")


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("execution_backend")
