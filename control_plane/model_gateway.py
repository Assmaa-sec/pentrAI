"""Private managed-model proxy; provider credentials stay outside runner Pods."""

from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import httpx
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from execution_manager.model_tokens import ModelTokenRejected, verify_model_token
from .credits import CreditRejected, record_model_usage, require_model_budget
from .model_catalog import ModelOption
from .models import Scan


def create_model_gateway(
    engine: Engine, signing_key: bytes, upstream_base_url: str = "",
    upstream_api_key: str = "", upstream_model: str = "", *,
    dynamic_scans_enabled: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
    catalog: dict[str, ModelOption] | None = None,
) -> FastAPI:
    parsed = urlsplit(upstream_base_url)
    if (len(signing_key) < 32 or (catalog is None and (
            parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path.rstrip("/") != "/v1" or not upstream_api_key
            or not upstream_model)) or (catalog is not None and not catalog)):
        raise ValueError("managed model gateway configuration is invalid")
    app = FastAPI(title="PentrAI Private Model Gateway", docs_url=None, redoc_url=None)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) > 4200:
            raise HTTPException(status_code=403, detail="model access rejected")
        with Session(engine) as session:
            try:
                lease = verify_model_token(session, authorization[7:], signing_key,
                                           dynamic_scans_enabled=dynamic_scans_enabled)
                require_model_budget(session, lease.scan_id)
                scan_id = lease.scan_id
                scan = session.get(Scan, scan_id)
                if scan is None:
                    raise ModelTokenRejected("scan missing")
                if catalog is not None:
                    option = catalog.get(scan.model_id)
                    if (option is None or option.prompt_credit_rate != scan.prompt_credit_rate
                            or option.completion_credit_rate != scan.completion_credit_rate):
                        raise ModelTokenRejected("selected model changed")
                    selected_url = option.base_url
                    selected_model = option.provider_model
                    selected_key = os.getenv(option.key_env, "")
                    if not selected_key:
                        raise ModelTokenRejected("selected model unavailable")
                else:
                    if scan.model_id != "managed":
                        raise ModelTokenRejected("selected model unavailable")
                    selected_url, selected_model, selected_key = (
                        upstream_base_url, upstream_model, upstream_api_key)
            except (ModelTokenRejected, CreditRejected):
                raise HTTPException(status_code=403, detail="model access rejected") from None
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 2 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="model request exceeds limit")
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="invalid model request") from None
        if (not isinstance(payload, dict) or payload.get("model") != "managed"
                or payload.get("stream") is True
                or not isinstance(payload.get("messages"), list)
                or not 1 <= len(payload["messages"]) <= 128
                or set(payload) - {"model", "messages", "temperature", "tools",
                                   "tool_choice", "response_format", "stream"}):
            raise HTTPException(status_code=400, detail="invalid model request")
        forwarded = {**payload, "model": selected_model, "stream": False}
        try:
            async with httpx.AsyncClient(timeout=120, follow_redirects=False,
                                         trust_env=False, transport=transport) as client:
                async with client.stream(
                    "POST", selected_url.rstrip("/") + "/chat/completions",
                    json=forwarded,
                    headers={"Authorization": f"Bearer {selected_key}"},
                ) as response:
                    if response.status_code != 200:
                        raise ValueError("upstream response failed")
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > 2 * 1024 * 1024:
                            raise ValueError("upstream response exceeds limit")
            result = json.loads(content)
            if (not isinstance(result, dict) or not isinstance(result.get("choices"), list)
                    or not isinstance(result.get("usage"), dict) or not result["usage"]):
                raise ValueError("invalid upstream response")
            with Session(engine) as session:
                record_model_usage(session, scan_id, result["usage"])
                session.commit()
        except (httpx.HTTPError, ValueError, CreditRejected):
            raise HTTPException(status_code=502, detail="managed model unavailable") from None
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    return app
