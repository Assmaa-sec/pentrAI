"""Alembic environment for the control-plane PostgreSQL schema."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, pool

from control_plane.models import Base


config = context.config
target_metadata = Base.metadata
database_url = os.environ.get("PENTRAI_DATABASE_URL")
if not database_url:
    raise RuntimeError("PENTRAI_DATABASE_URL is required for migrations")


def run_migrations_offline() -> None:
    context.configure(url=database_url, target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
