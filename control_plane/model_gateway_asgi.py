"""Private managed-model gateway ASGI entrypoint."""

from __future__ import annotations

import os

from sqlalchemy import create_engine

from .model_gateway import create_model_gateway
from .model_catalog import model_options


app = create_model_gateway(
    create_engine(os.environ["PENTRAI_DATABASE_URL"], pool_pre_ping=True),
    os.environ["PENTRAI_GRANT_SIGNING_KEY"].encode("utf-8"),
    catalog=model_options(),
)
