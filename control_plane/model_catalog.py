"""Operator-configured model choices; provider credentials never reach the browser."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ModelOption:
    id: str
    label: str
    provider_model: str
    base_url: str
    key_env: str
    prompt_credit_rate: int
    completion_credit_rate: int

    def public(self) -> dict[str, str | int]:
        return {"id": self.id, "label": self.label,
                "prompt_credit_rate": self.prompt_credit_rate,
                "completion_credit_rate": self.completion_credit_rate}


def model_options() -> dict[str, ModelOption]:
    """Read a deployment-owned catalog, never a customer-supplied endpoint."""
    raw = os.getenv("PENTRAI_MODEL_OPTIONS_JSON")
    if raw is None:
        raw = json.dumps([{
            "id": "managed", "label": "Recommended model",
            "provider_model": os.getenv("PENTRAI_LLM_MODEL", "deepseek-chat"),
            "base_url": os.getenv("PENTRAI_LLM_BASE_URL", "http://127.0.0.1:8889/v1"),
            "key_env": "PENTRAI_LLM_API_KEY",
            "prompt_credit_rate": 1, "completion_credit_rate": 1,
        }])
    try:
        items = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("model catalog is invalid") from exc
    if not isinstance(items, list) or not 1 <= len(items) <= 20:
        raise ValueError("model catalog must contain 1-20 options")
    catalog: dict[str, ModelOption] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "id", "label", "provider_model", "base_url", "key_env",
            "prompt_credit_rate", "completion_credit_rate",
        }:
            raise ValueError("model catalog entry is invalid")
        try:
            option = ModelOption(**item)
            parsed = urlsplit(option.base_url)
        except (TypeError, ValueError) as exc:
            raise ValueError("model catalog entry is invalid") from exc
        if (not isinstance(option.id, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", option.id)
                or option.id in catalog or not isinstance(option.label, str)
                or not 1 <= len(option.label) <= 80
                or not isinstance(option.provider_model, str) or not option.provider_model
                or not isinstance(option.key_env, str)
                or not re.fullmatch(r"PENTRAI_[A-Z0-9_]{1,80}", option.key_env)
                or parsed.scheme not in {"https", "http"} or not parsed.hostname
                or (parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"})
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path.rstrip("/") != "/v1"
                or type(option.prompt_credit_rate) is not int
                or type(option.completion_credit_rate) is not int
                or not 1 <= option.prompt_credit_rate <= 1000
                or not 1 <= option.completion_credit_rate <= 1000):
            raise ValueError("model catalog entry is invalid")
        catalog[option.id] = option
    return catalog
