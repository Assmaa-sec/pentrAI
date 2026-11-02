"""Versioned JSON representation of the local pipeline result."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from .contracts import PipelineResult, Target


PIPELINE_RESULT_SCHEMA_VERSION = 1


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _json_value(getattr(value, item.name))
            for item in fields(value)
            if not (isinstance(value, Target) and item.name == "secrets_path")
        }
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported pipeline result value: {type(value).__name__}")


def pipeline_result_dict(result: PipelineResult) -> dict[str, Any]:
    """Return a JSON-ready envelope without exposing the credentials file path."""
    return {
        "schema_version": PIPELINE_RESULT_SCHEMA_VERSION,
        "result": _json_value(result),
    }
