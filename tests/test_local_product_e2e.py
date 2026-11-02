"""Exercise the local HTTP contract and real offline worker as one workflow."""

from __future__ import annotations

import hashlib
import io
import shutil
import time
import unittest
import uuid
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from control_plane.app import create_app
from control_plane.auth import mint_local_token
from control_plane.local_store import LocalObjectStore
from control_plane.local_worker import run_once
from control_plane.models import Base, Membership, Organization, Project, Scan, ScanGrant, ScanState, User
from control_plane.settings import Settings
from static_worker.osv import OfflineOSVScanner
from tests.test_offline_osv_adapter import DB_SHA256, SCANNER_SHA256


@unittest.skipUnless(
    Path(".tmp/osv-scanner.exe").exists() and Path(".tmp/osvdb/osv-scalibr/PyPI/all.zip").exists(),
    "pinned offline OSV fixture assets are not installed",
)
class LocalProductEndToEndTests(unittest.TestCase):
    def test_upload_scan_worker_and_report_exports(self):
        root = Path(".tmp/local-product-e2e") / uuid.uuid4().hex
        root.mkdir(parents=True)
        engine = create_engine(f"sqlite+pysqlite:///{(root / 'control.db').as_posix()}")
        client = None
        try:
            Base.metadata.create_all(engine)
            with Session(engine) as session:
                organization = Organization(name="Local end-to-end fixture")
                user = User(oidc_subject="urn:pentrai:local|e2e-owner")
                session.add_all([organization, user])
                session.flush()
                project = Project(organization_id=organization.id, name="Guinea Pig")
                session.add_all([project, Membership(
                    organization_id=organization.id, user_id=user.id, role="owner",
                )])
                session.commit()
                organization_id, project_id = organization.id, project.id

            signing_key = b"local-e2e-signing-key-32-bytes-minimum"
            token = mint_local_token("e2e-owner", signing_key, int(time.time()) + 300)
            settings = Settings(
                database_url=f"sqlite+pysqlite:///{(root / 'control.db').as_posix()}",
                grant_signing_key=signing_key.decode(),
                local_artifact_root=str(root / "artifacts"), local_dev_auth=True,
                local_static_enabled=True,
            )
            client = TestClient(create_app(settings))
            prefix = f"/v1/organizations/{organization_id}"
            headers = {"Authorization": f"Bearer {token}"}
            self.assertEqual(401, client.get(f"{prefix}/projects/{project_id}").status_code)
            self.assertEqual(200, client.get(f"{prefix}/projects/{project_id}", headers=headers).status_code)

            archive_buffer = io.BytesIO()
            with zipfile.ZipFile(archive_buffer, "w") as archive:
                archive.writestr("requirements.txt", Path("guinea_pig/target/requirements.txt").read_bytes())
            source = archive_buffer.getvalue()
            upload = client.post(
                f"{prefix}/projects/{project_id}/uploads",
                json={"content_type": "application/zip", "declared_bytes": len(source)},
                headers={**headers, "Idempotency-Key": "e2e-upload"},
            )
            self.assertEqual(201, upload.status_code, upload.text)
            upload_id = upload.json()["id"]
            uploaded = client.put(
                f"{prefix}/uploads/{upload_id}", content=source,
                headers={**headers, "Content-Type": "application/zip"},
            )
            self.assertEqual(204, uploaded.status_code, uploaded.text)
            finalized = client.post(
                f"{prefix}/uploads/{upload_id}/finalize",
                json={"sha256": hashlib.sha256(source).hexdigest()}, headers=headers,
            )
            self.assertEqual(201, finalized.status_code, finalized.text)
            created = client.post(
                f"{prefix}/projects/{project_id}/scans",
                json={"source_artifact_id": finalized.json()["id"],
                      "scope_note": "Owned local fixture", "profile": "standard", "authorized": True},
                headers={**headers, "Idempotency-Key": "e2e-scan"},
            )
            self.assertEqual(201, created.status_code, created.text)
            scan_id = created.json()["id"]
            self.assertEqual("authorized", created.json()["state"])
            scanner_workspace = root / "scanner"
            scanner_workspace.mkdir()
            scanner = OfflineOSVScanner(
                Path(".tmp/osv-scanner.exe"), SCANNER_SHA256,
                Path(".tmp/osvdb"), DB_SHA256, scanner_workspace,
            )
            run_once(engine, organization_id, scan_id, signing_key,
                     LocalObjectStore(root / "artifacts"), scanner, root / "jobs")

            scan_path = f"{prefix}/scans/{scan_id}"
            state = client.get(scan_path, headers=headers)
            self.assertEqual(200, state.status_code, state.text)
            self.assertEqual("completed", state.json()["state"])
            findings = client.get(f"{scan_path}/findings", headers=headers)
            self.assertEqual(200, findings.status_code, findings.text)
            self.assertGreaterEqual(len(findings.json()), 4)
            summary = client.get(f"{prefix}/workspace-summary", headers=headers)
            self.assertEqual(200, summary.status_code, summary.text)
            self.assertEqual({"projects": 1, "assessments": 1, "completed": 1,
                              "findings": len(findings.json())}, summary.json())
            all_scans = client.get(f"{prefix}/scans", headers=headers)
            self.assertEqual(200, all_scans.status_code, all_scans.text)
            self.assertEqual(scan_id, all_scans.json()[0]["id"])
            self.assertEqual("Guinea Pig", all_scans.json()[0]["project_name"])
            all_findings = client.get(f"{prefix}/findings", headers=headers)
            self.assertEqual(200, all_findings.status_code, all_findings.text)
            self.assertEqual(len(findings.json()), len(all_findings.json()))
            self.assertTrue(all(item["scan_id"] == scan_id for item in all_findings.json()))
            for endpoint in ("workspace-summary", "scans", "findings"):
                self.assertEqual(401, client.get(f"{prefix}/{endpoint}").status_code)
            report = client.get(f"{scan_path}/report", headers=headers)
            self.assertEqual(200, report.status_code, report.text)
            self.assertIn("detected", report.json()["markdown"].lower())
            events = client.get(f"{scan_path}/events?follow=false", headers=headers)
            self.assertEqual(200, events.status_code, events.text)
            self.assertIn("Assessment", events.text)
            for extension, signature in (("md", b"#"), ("pdf", b"%PDF"), ("docx", b"PK")):
                with self.subTest(extension=extension):
                    exported = client.get(f"{scan_path}/report.{extension}", headers=headers)
                    self.assertEqual(200, exported.status_code, exported.text[:500])
                    self.assertTrue(exported.content.startswith(signature))
                    self.assertEqual("no-store", exported.headers["cache-control"])
            answer = client.post(f"{scan_path}/questions", json={"question": "What is the scan status?"}, headers=headers)
            self.assertEqual(200, answer.status_code, answer.text)
            self.assertIn("completed", answer.json()["answer"])
            with Session(engine) as session:
                self.assertEqual(ScanState.COMPLETED, session.get(Scan, scan_id).state)
                self.assertFalse(session.scalars(select(ScanGrant).where(
                    ScanGrant.scan_id == scan_id, ScanGrant.revoked_at.is_(None),
                )).first())
            self.assertFalse((root / "jobs" / scan_id).exists())
        finally:
            if client is not None:
                client.close()
                client.app.state.engine.dispose()
            engine.dispose()
            shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main()
