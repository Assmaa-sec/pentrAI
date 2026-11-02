"""Environment-configured ASGI entry point for local and later deployed servers."""

from .app import create_app
from .settings import Settings

app = create_app(Settings.from_env())
