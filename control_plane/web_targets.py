"""Public web-target normalization and proof of control.

Verification makes one bounded request to a pinned public IP. It never follows
redirects or hands the customer URL to the control plane's HTTP client.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import ipaddress
import re
import secrets
import socket
import ssl
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Membership, Project, WebTargetProof


class WebTargetRejected(ValueError):
    pass


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def normalize_target_url(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or len(value) > 2048 or value != value.strip():
        raise WebTargetRejected("invalid web target URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError as exc:
        raise WebTargetRejected("invalid web target URL") from exc
    if (parsed.scheme not in {"http", "https"} or not host or parsed.username is not None
            or parsed.password is not None or parsed.fragment or not parsed.netloc):
        raise WebTargetRejected("web target must be an HTTP or HTTPS URL without credentials or fragment")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise WebTargetRejected("invalid web target host") from exc
        if (len(host) > 253 or not re.fullmatch(r"[a-z0-9.-]+", host)
                or any(not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
                       for label in host.split("."))):
            raise WebTargetRejected("invalid web target host")
    else:
        if not address.is_global:
            raise WebTargetRejected("web target address must be public")
        host = address.compressed
    if port is not None and not 1 <= port <= 65535:
        raise WebTargetRejected("invalid web target port")
    default_port = 443 if parsed.scheme == "https" else 80
    origin_host = f"[{host}]" if ":" in host else host
    origin = f"{parsed.scheme}://{origin_host}"
    if port and port != default_port:
        origin += f":{port}"
    path = parsed.path or "/"
    normalized = urlunsplit((parsed.scheme, origin[len(parsed.scheme) + 3:], path, parsed.query, ""))
    if len(normalized) > 2048:
        raise WebTargetRejected("web target URL is too long")
    return normalized, origin


def start_web_proof(
    session: Session, organization_id: str, project_id: str, actor_id: str,
    target_url: str, *, now: datetime | None = None,
) -> tuple[WebTargetProof, str]:
    _, origin = normalize_target_url(target_url)
    membership = session.scalar(select(Membership).where(
        Membership.organization_id == organization_id, Membership.user_id == actor_id))
    project = session.scalar(select(Project).where(
        Project.id == project_id, Project.organization_id == organization_id))
    if membership is None or membership.role not in {"owner", "security_engineer"} or project is None:
        raise WebTargetRejected("project or authorized member not found")
    token = secrets.token_urlsafe(32)
    now = now or datetime.now(timezone.utc)
    proof = WebTargetProof(
        organization_id=organization_id, project_id=project_id, created_by=actor_id,
        origin=origin, token_sha256=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=now + timedelta(minutes=15),
    )
    session.add(proof)
    session.flush()
    return proof, token


def fetch_public_challenge(origin: str, proof_id: str) -> bytes:
    parsed = urlsplit(origin)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host or parsed.scheme not in {"http", "https"}:
        raise WebTargetRejected("invalid proof origin")
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise WebTargetRejected("web target DNS lookup failed") from exc
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise WebTargetRejected("web target DNS must resolve only to public addresses")
    address = addresses[0][4][0]
    host_header = parsed.netloc
    request = (f"GET /.well-known/pentrai-verification/{proof_id} HTTP/1.1\r\n"
               f"Host: {host_header}\r\nConnection: close\r\nAccept: text/plain\r\n\r\n").encode("ascii")
    try:
        with socket.create_connection((address, port), timeout=5) as raw:
            raw.settimeout(5)
            if parsed.scheme == "https":
                connection = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            else:
                connection = raw
            with connection:
                connection.sendall(request)
                response = http.client.HTTPResponse(connection)
                response.begin()
                if response.status != 200:
                    raise WebTargetRejected("web target proof file was not found")
                body = response.read(4097)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise WebTargetRejected("web target proof request failed") from exc
    if len(body) > 4096:
        raise WebTargetRejected("web target proof response is too large")
    return body


def verify_web_proof(
    session: Session, organization_id: str, project_id: str, actor_id: str,
    proof_id: str, *, now: datetime | None = None, fetcher=fetch_public_challenge,
) -> WebTargetProof:
    proof = session.scalar(select(WebTargetProof).where(
        WebTargetProof.id == proof_id, WebTargetProof.organization_id == organization_id,
        WebTargetProof.project_id == project_id))
    membership = session.scalar(select(Membership).where(
        Membership.organization_id == organization_id, Membership.user_id == actor_id))
    if proof is None or membership is None or membership.role not in {"owner", "security_engineer"}:
        raise WebTargetRejected("web target proof not found")
    now = now or datetime.now(timezone.utc)
    if now >= _aware(proof.expires_at):
        raise WebTargetRejected("web target proof expired")
    if proof.verified_at is not None:
        return proof
    body = fetcher(proof.origin, proof.id)
    if not isinstance(body, bytes) or len(body) > 4096:
        raise WebTargetRejected("invalid web target proof response")
    try:
        supplied = body.strip().decode("ascii")
    except UnicodeError as exc:
        raise WebTargetRejected("invalid web target proof response") from exc
    if not secrets.compare_digest(hashlib.sha256(supplied.encode()).hexdigest(), proof.token_sha256):
        raise WebTargetRejected("web target proof token did not match")
    proof.verified_at = now
    proof.verified_until = now + timedelta(days=1)
    session.flush()
    return proof
