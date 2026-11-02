"""persist idempotent project creation keys

Revision ID: b91c7f6e3a02
Revises: 8a7e51c2d4b0
"""

from alembic import op
import sqlalchemy as sa

revision = "b91c7f6e3a02"
down_revision = "8a7e51c2d4b0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "project_create_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("key", sa.String(200), nullable=False),
        sa.Column("name_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "key"),
    )
    op.create_index("ix_project_create_records_organization_id", "project_create_records", ["organization_id"])


def downgrade() -> None:
    op.drop_index("ix_project_create_records_organization_id", table_name="project_create_records")
    op.drop_table("project_create_records")
