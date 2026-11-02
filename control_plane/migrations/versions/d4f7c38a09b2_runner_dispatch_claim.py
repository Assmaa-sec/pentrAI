"""Persist worker claim and launch acknowledgement for runner leases.

Revision ID: d4f7c38a09b2
Revises: c28a9d5e63b4
"""

from alembic import op
import sqlalchemy as sa

revision = "d4f7c38a09b2"
down_revision = "c28a9d5e63b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("runner_leases") as batch:
        batch.add_column(sa.Column("dispatch_owner", sa.String(36), nullable=True))
        batch.add_column(sa.Column("dispatch_claim_until", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("dispatch_attempts", sa.Integer(), nullable=False,
                                   server_default="0"))
        batch.add_column(sa.Column("launched_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("runner_leases") as batch:
        batch.drop_column("launched_at")
        batch.drop_column("dispatch_attempts")
        batch.drop_column("dispatch_claim_until")
        batch.drop_column("dispatch_owner")
