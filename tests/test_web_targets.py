from datetime import datetime, timedelta, timezone
import hashlib
import socket
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from control_plane.grants import GrantError, issue_grant, verify_grant
from control_plane.credits import grant_credits
from control_plane.organization_authorization import approve_authorization
from control_plane.models import (Base, Membership, Organization, OutboxEvent,
                                  Project, Scan, SourceArtifact, UploadGrantRecord, User)
from control_plane.scan_creation import CreateScanRejected, create_scan
from control_plane.web_targets import (WebTargetRejected, fetch_public_challenge,
                                       normalize_target_url, start_web_proof, verify_web_proof)


class WebTargetTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as session:
            session.add_all([
                Organization(id="org", name="Organization"),
                Organization(id="other", name="Other"),
                User(id="owner", oidc_subject="owner"),
                Project(id="project", organization_id="org", name="Project"),
                Membership(id="member", organization_id="org", user_id="owner", role="owner"),
            ])
            session.commit()
            approve_authorization(session, "org", "owner",
                                  scope_statement="Company-owned web target and source fixture",
                                  source_allowed=True, url_allowed=True, valid_days=1,
                                  accept_terms=True)
            grant_credits(session, "org", 1_000_000,
                          actor_id="owner", reason="test fixture")
            session.commit()

    def tearDown(self):
        self.engine.dispose()

    def test_normalization_and_private_rejection(self):
        self.assertEqual(normalize_target_url("https://Example.COM:443/app?q=1"),
                         ("https://example.com/app?q=1", "https://example.com"))
        for value in ("http://127.0.0.1", "http://[::1]/", "http://user:pw@example.com",
                      "file:///etc/passwd", "https://example.com/#fragment"):
            with self.subTest(value=value), self.assertRaises(WebTargetRejected):
                normalize_target_url(value)

    def test_dns_private_answer_rejected_before_connect(self):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("control_plane.web_targets.socket.getaddrinfo", return_value=answer):
            with patch("control_plane.web_targets.socket.create_connection") as connect:
                with self.assertRaisesRegex(WebTargetRejected, "public"):
                    fetch_public_challenge("https://example.com", "proof-id")
                connect.assert_not_called()

    def test_proof_binds_url_only_scan_and_grant(self):
        now = datetime.now(timezone.utc)
        with Session(self.engine) as session:
            proof, token = start_web_proof(session, "org", "project", "owner",
                                            "https://example.com/app", now=now)
            with self.assertRaises(CreateScanRejected):
                create_scan(session, "org", "project", "owner", None,
                    scope_note="owned site", profile="standard", authorized=True,
                    idempotency_key="too-early", target_url="https://example.com/app",
                    web_target_proof_id=proof.id)
            verified = verify_web_proof(session, "org", "project", "owner", proof.id,
                now=now, fetcher=lambda origin, identifier: token.encode())
            self.assertEqual(verified.origin, "https://example.com")
            scan = create_scan(session, "org", "project", "owner", None,
                scope_note="owned site", profile="standard", authorized=True,
                idempotency_key="url-only", target_url="https://example.com/app",
                web_target_proof_id=proof.id)
            self.assertEqual(scan.source_digest, hashlib.sha256(b"").hexdigest())
            self.assertTrue(scan.dynamic_authorized)
            self.assertEqual(session.scalar(select(OutboxEvent).where(
                OutboxEvent.scan_id == scan.id)).kind, "scan.create.hexstrike")
            grant = issue_grant(session, scan, b"k" * 32, timedelta(minutes=5), now=now)
            claims = verify_grant(session, grant, b"k" * 32, scan.source_digest, now=now)
            self.assertEqual(claims.target_url, scan.target_url)
            scan.target_url = "https://example.com/other"
            with self.assertRaisesRegex(GrantError, "binding"):
                verify_grant(session, grant, b"k" * 32, scan.source_digest, now=now)

    def test_mismatch_and_bad_token_rejected(self):
        with Session(self.engine) as session:
            proof, _ = start_web_proof(session, "org", "project", "owner", "https://example.com")
            with self.assertRaisesRegex(WebTargetRejected, "token"):
                verify_web_proof(session, "org", "project", "owner", proof.id,
                                 fetcher=lambda _origin, _identifier: b"wrong")
            with self.assertRaises(CreateScanRejected):
                create_scan(session, "org", "project", "owner", None,
                    scope_note="owned", profile="standard", authorized=True,
                    idempotency_key="wrong-origin", target_url="https://other.example.com/",
                    web_target_proof_id=proof.id)

    def test_combined_source_and_url_preserves_both_bindings(self):
        with Session(self.engine) as session:
            upload = UploadGrantRecord(
                organization_id="org", project_id="project", created_by="owner",
                object_key="combined.zip", content_type="application/zip", declared_bytes=1,
                idempotency_key="combined-upload", expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
            session.add(upload)
            session.flush()
            artifact = SourceArtifact(
                organization_id="org", project_id="project", upload_grant_id=upload.id,
                object_key="combined.zip", sha256="d" * 64, size_bytes=1,
                content_type="application/zip")
            session.add(artifact)
            session.flush()
            proof, token = start_web_proof(session, "org", "project", "owner", "https://example.com")
            verify_web_proof(session, "org", "project", "owner", proof.id,
                             fetcher=lambda _origin, _id: token.encode())
            scan = create_scan(session, "org", "project", "owner", artifact.id,
                scope_note="both targets", profile="deep", authorized=True,
                idempotency_key="combined", target_url="https://example.com/app",
                web_target_proof_id=proof.id)
            self.assertEqual(scan.source_digest, "d" * 64)
            self.assertEqual(scan.target_url, "https://example.com/app")
            self.assertEqual(scan.source_artifact_id, artifact.id)
