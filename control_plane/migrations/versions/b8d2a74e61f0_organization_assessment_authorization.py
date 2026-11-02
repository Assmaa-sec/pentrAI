"""Bind native scans to owner-approved organization assessment authority.

Revision ID: b8d2a74e61f0
Revises: a7e1c42d90b3
"""

from alembic import op
import sqlalchemy as sa

revision = "b8d2a74e61f0"
down_revision = "a7e1c42d90b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table = "organization_assessment_authorizations"
    # SQLite can retain DDL after a failed batch rebuild; resume safely there.
    if table not in inspector.get_table_names():
        op.create_table(
            table,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("approved_by", sa.String(36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("scope_statement", sa.String(2000), nullable=False),
            sa.Column("terms_version", sa.String(32), nullable=False),
            sa.Column("source_allowed", sa.Boolean(), nullable=False),
            sa.Column("url_allowed", sa.Boolean(), nullable=False),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        )
    inspector = sa.inspect(bind)
    if "ix_organization_assessment_authorizations_organization_id" not in {
        item["name"] for item in inspector.get_indexes(table)
    }:
        op.create_index("ix_organization_assessment_authorizations_organization_id",
                        table, ["organization_id"])
    if "authorization_id" not in {item["name"] for item in inspector.get_columns("scans")}:
        with op.batch_alter_table("scans") as batch:
            batch.add_column(sa.Column("authorization_id", sa.String(36),
                                       sa.ForeignKey(table + ".id", ondelete="RESTRICT",
                                                     name="fk_scans_authorization_id"),
                                       nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("authorization_id")
    op.drop_index("ix_organization_assessment_authorizations_organization_id",
                  table_name="organization_assessment_authorizations")
    op.drop_table("organization_assessment_authorizations")
