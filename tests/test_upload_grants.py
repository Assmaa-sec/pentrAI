from __future__ import annotations

import hashlib
import json
import os
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from control_plane.models import Base, Membership, Organization, Project, User


class FakeObjectStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def read_chunks(self, key: str):
        data = self.objects[key]
        for offset in range(0, len(data), 1024):
            yield data[offset:offset + 1024]


class UploadGrantTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        org = Organization(name="Northstar")
        foreign = Organization(name="Southstar")
        user = User(oidc_subject="id|one")
        self.session.add_all([org, foreign, user])
        self.session.flush()
        self.session.add(Membership(organization_id=org.id, user_id=user.id, role="owner"))
        project = Project(organization_id=org.id, name="Payments")
        self.session.add(project)
        self.session.commit()
        self.org_id, self.foreign_id, self.project_id, self.user_id = org.id, foreign.id, project.id, user.id
        self.store = FakeObjectStore()
        from control_plane.credits import grant_credits
        from control_plane.organization_authorization import approve_authorization
        approve_authorization(self.session, self.org_id, self.user_id,
                              scope_statement="Company-owned source assessment fixture",
                              source_allowed=True, url_allowed=False, valid_days=1,
                              accept_terms=True)
        grant_credits(self.session, self.org_id, 1_000_000,
                      actor_id=self.user_id, reason="test fixture")
        self.session.commit()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_finalization_hashes_stored_bytes_and_rejects_other_org_key(self):
        from control_plane.artifacts import UploadRejected, create_upload_grant, finalize_upload
        from control_plane.models import AuditEvent, OutboxEvent

        grant = create_upload_grant(
            self.session, self.org_id, self.project_id, self.user_id,
            content_type="application/zip", declared_bytes=7, idempotency_key="upload-1",
        )
        self.assertTrue(grant.object_key.startswith(f"organizations/{self.org_id}/projects/{self.project_id}/"))
        self.store.objects[grant.object_key] = b"ZIPDATA"
        with self.assertRaisesRegex(UploadRejected, "object key"):
            finalize_upload(
                self.session, grant.id, self.org_id, self.user_id, self.store,
                claimed_sha256=hashlib.sha256(b"ZIPDATA").hexdigest(),
                object_key=f"organizations/{self.foreign_id}/other.zip",
            )
        artifact = finalize_upload(
            self.session, grant.id, self.org_id, self.user_id, self.store,
            claimed_sha256=hashlib.sha256(b"ZIPDATA").hexdigest(), object_key=grant.object_key,
        )
        self.session.commit()
        self.assertEqual(hashlib.sha256(b"ZIPDATA").hexdigest(), artifact.sha256)
        upload_events = self.session.scalars(select(AuditEvent).where(
            AuditEvent.action.like("upload.%"))).all()
        self.assertEqual(2, len(upload_events))
        events = self.session.scalars(select(OutboxEvent)).all()
        self.assertEqual(2, len(events))
        self.assertEqual(artifact.id, events[-1].payload["artifact_id"])

    def test_cross_tenant_or_wrong_digest_cannot_finalize(self):
        from control_plane.artifacts import UploadRejected, create_upload_grant, finalize_upload

        grant = create_upload_grant(
            self.session, self.org_id, self.project_id, self.user_id,
            content_type="application/zip", declared_bytes=3, idempotency_key="upload-2",
        )
        self.store.objects[grant.object_key] = b"abc"
        with self.assertRaises(UploadRejected):
            finalize_upload(self.session, grant.id, self.foreign_id, self.user_id, self.store, "0" * 64, grant.object_key)
        with self.assertRaisesRegex(UploadRejected, "digest"):
            finalize_upload(self.session, grant.id, self.org_id, self.user_id, self.store, "0" * 64, grant.object_key)

    def test_scan_creation_binds_finalized_artifact_and_idempotency(self):
        from control_plane.artifacts import create_upload_grant, finalize_upload
        from control_plane.models import ScanState
        from control_plane.scan_creation import CreateScanRejected, create_scan

        grant = create_upload_grant(
            self.session, self.org_id, self.project_id, self.user_id,
            content_type="application/zip", declared_bytes=3, idempotency_key="upload-3",
        )
        self.store.objects[grant.object_key] = b"abc"
        artifact = finalize_upload(
            self.session, grant.id, self.org_id, self.user_id, self.store,
            hashlib.sha256(b"abc").hexdigest(), grant.object_key,
        )
        scan = create_scan(
            self.session, self.org_id, self.project_id, self.user_id, artifact.id,
            scope_note="company-owned fixture", profile="standard", authorized=True,
            idempotency_key="scan-1",
        )
        repeat = create_scan(
            self.session, self.org_id, self.project_id, self.user_id, artifact.id,
            scope_note="company-owned fixture", profile="standard", authorized=True,
            idempotency_key="scan-1",
        )
        self.assertEqual(scan.id, repeat.id)
        self.assertEqual(ScanState.AUTHORIZED, scan.state)
        self.assertEqual(artifact.sha256, scan.source_digest)
        self.assertFalse(scan.dynamic_authorized)
        option = {"id": "deep-model", "label": "Deep model", "provider_model": "provider-deep",
                  "base_url": "https://provider.example/v1", "key_env": "PENTRAI_DEEP_KEY",
                  "prompt_credit_rate": 2, "completion_credit_rate": 4}
        with patch.dict(os.environ, {"PENTRAI_MODEL_OPTIONS_JSON": json.dumps([option])}):
            selected = create_scan(
                self.session, self.org_id, self.project_id, self.user_id, artifact.id,
                scope_note="company-owned fixture", profile="standard", authorized=False,
                idempotency_key="scan-deep-model", model_id="deep-model",
            )
        self.assertEqual("deep-model", selected.model_id)
        self.assertEqual((2, 4), (selected.prompt_credit_rate, selected.completion_credit_rate))
        with self.assertRaises(CreateScanRejected):
            create_scan(
                self.session, self.foreign_id, self.project_id, self.user_id, artifact.id,
                scope_note="other", profile="standard", authorized=True,
                idempotency_key="scan-foreign",
            )


if __name__ == "__main__":
    unittest.main()
