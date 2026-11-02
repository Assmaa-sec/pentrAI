"""Retain model usage even when a scan fails after a provider response.

Revision ID: d0f4c96a83b2
Revises: c9e3b85f72a1
"""

from alembic import op
import sqlalchemy as sa

revision = "d0f4c96a83b2"
down_revision = "c9e3b85f72a1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scan_credit_reservations") as batch:
        batch.add_column(sa.Column("metered_credits", sa.Integer(), nullable=False,
                                   server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("scan_credit_reservations") as batch:
        batch.drop_column("metered_credits")
