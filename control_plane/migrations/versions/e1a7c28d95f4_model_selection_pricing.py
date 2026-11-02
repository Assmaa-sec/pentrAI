"""Bind each scan to a selected model and immutable per-token credit rates.

Revision ID: e1a7c28d95f4
Revises: d0f4c96a83b2
"""

from alembic import op
import sqlalchemy as sa

revision = "e1a7c28d95f4"
down_revision = "d0f4c96a83b2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("model_id", sa.String(40), nullable=False, server_default="managed"))
        batch.add_column(sa.Column("prompt_credit_rate", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("completion_credit_rate", sa.Integer(), nullable=False, server_default="1"))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("completion_credit_rate")
        batch.drop_column("prompt_credit_rate")
        batch.drop_column("model_id")
