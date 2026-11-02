"""bind scans to source artifacts

Revision ID: e6952c1809fa
Revises: 699522dc3b99
Create Date: 2026-10-03 19:49:00.337940

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e6952c1809fa'
down_revision: Union[str, Sequence[str], None] = '699522dc3b99'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('scans') as batch:
        batch.add_column(sa.Column('source_artifact_id', sa.String(length=36), nullable=True))
        batch.create_foreign_key(
            'fk_scans_source_artifact_id', 'source_artifacts',
            ['source_artifact_id'], ['id'], ondelete='RESTRICT',
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('scans') as batch:
        batch.drop_constraint('fk_scans_source_artifact_id', type_='foreignkey')
        batch.drop_column('source_artifact_id')
