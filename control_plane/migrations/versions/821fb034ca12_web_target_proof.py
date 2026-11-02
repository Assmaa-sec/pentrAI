"""Add proof-bound web targets to scans.

Revision ID: 821fb034ca12
Revises: 4f21b8e0a719
"""

from alembic import op
import sqlalchemy as sa

revision = "821fb034ca12"
down_revision = "4f21b8e0a719"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "web_target_proofs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("origin", sa.String(500), nullable=False),
        sa.Column("token_sha256", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_web_target_proofs_organization_id", "web_target_proofs", ["organization_id"])
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("target_url", sa.String(2048), nullable=True))
        batch.add_column(sa.Column("web_target_proof_id", sa.String(36), nullable=True))
        batch.create_foreign_key("fk_scans_web_target_proof_id", "web_target_proofs", ["web_target_proof_id"], ["id"], ondelete="RESTRICT")


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("fk_scans_web_target_proof_id", type_="foreignkey")
        batch.drop_column("web_target_proof_id")
        batch.drop_column("target_url")
    op.drop_index("ix_web_target_proofs_organization_id", table_name="web_target_proofs")
    op.drop_table("web_target_proofs")
