"""persist runner leases and cleanup state

Revision ID: 8a7e51c2d4b0
Revises: 0d4e17b3f2c1
"""

from alembic import op
import sqlalchemy as sa

revision = "8a7e51c2d4b0"
down_revision = "0d4e17b3f2c1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runner_leases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("scan_grant_id", sa.String(36), sa.ForeignKey("scan_grants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("namespace", sa.String(63), nullable=False, unique=True),
        sa.Column("service_account", sa.String(63), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cleaned_at", sa.DateTime(timezone=True)),
        sa.Column("artifact_grant_revoked_at", sa.DateTime(timezone=True)),
        sa.Column("cleanup_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cleanup_error", sa.String(200)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_runner_leases_organization_id", "runner_leases", ["organization_id"])
    op.create_index("ix_runner_leases_scan_id", "runner_leases", ["scan_id"])
    op.create_index("ix_runner_leases_expires_at", "runner_leases", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_runner_leases_expires_at", table_name="runner_leases")
    op.drop_index("ix_runner_leases_scan_id", table_name="runner_leases")
    op.drop_index("ix_runner_leases_organization_id", table_name="runner_leases")
    op.drop_table("runner_leases")
