"""Add model explanation and evidence references to scan findings.

Revision ID: 4f21b8e0a719
Revises: b91c7f6e3a02
"""

from alembic import op
import sqlalchemy as sa

revision = "4f21b8e0a719"
down_revision = "b91c7f6e3a02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scan_findings") as batch:
        batch.add_column(sa.Column("title", sa.String(200), nullable=True))
        batch.add_column(sa.Column("severity", sa.String(16), nullable=True))
        batch.add_column(sa.Column("explanation", sa.Text(), nullable=True))
        batch.add_column(sa.Column("evidence_sha256", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scan_findings") as batch:
        batch.drop_column("evidence_sha256")
        batch.drop_column("explanation")
        batch.drop_column("severity")
        batch.drop_column("title")
