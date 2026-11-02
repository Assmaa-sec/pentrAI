"""Reserve and settle token credits for native scans.

Revision ID: c9e3b85f72a1
Revises: b8d2a74e61f0
"""

from alembic import op
import sqlalchemy as sa

revision = "c9e3b85f72a1"
down_revision = "b8d2a74e61f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organization_credit_accounts",
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("available", sa.Integer(), nullable=False),
        sa.Column("reserved", sa.Integer(), nullable=False),
        sa.Column("spent", sa.Integer(), nullable=False),
    )
    op.create_table(
        "scan_credit_reservations",
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reserved_credits", sa.Integer(), nullable=False),
        sa.Column("charged_credits", sa.Integer(), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_credit_reservations_organization_id",
                    "scan_credit_reservations", ["organization_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_credit_reservations_organization_id", table_name="scan_credit_reservations")
    op.drop_table("scan_credit_reservations")
    op.drop_table("organization_credit_accounts")
