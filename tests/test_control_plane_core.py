from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


class ControlPlaneCoreTests(unittest.TestCase):
    def setUp(self):
        from control_plane.models import Base, Membership, Organization, Project, Scan, User

        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        self.org = Organization(name="Northstar")
        self.other_org = Organization(name="Southstar")
        self.user = User(oidc_subject="issuer|subject")
        self.session.add_all([self.org, self.other_org, self.user])
        self.session.flush()
        self.session.add(Membership(organization_id=self.org.id, user_id=self.user.id, role="owner"))
        self.project = Project(organization_id=self.org.id, name="Payments")
        self.session.add(self.project)
        self.session.flush()
        self.scan = Scan(
            organization_id=self.org.id,
            project_id=self.project.id,
            source_digest="a" * 64,
            scope_digest="b" * 64,
            profile="standard",
            dynamic_authorized=False,
        )
        self.session.add(self.scan)
        self.session.commit()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_project_name_is_unique_within_organization(self):
        from control_plane.models import Project

        self.session.add(Project(organization_id=self.org.id, name="Payments"))
        with self.assertRaises(IntegrityError):
            self.session.flush()

    def test_transition_persists_audit_outbox_and_idempotency_once(self):
        from control_plane.models import AuditEvent, OutboxEvent, ScanState
        from control_plane.scans import transition_scan

        first = transition_scan(
            self.session, self.scan.id, self.org.id, self.user.id, ScanState.UPLOADED, "upload-k1"
        )
        second = transition_scan(
            self.session, self.scan.id, self.org.id, self.user.id, ScanState.UPLOADED, "upload-k1"
        )
        self.session.commit()

        self.assertEqual(first.audit_event_id, second.audit_event_id)
        self.assertEqual(ScanState.UPLOADED, self.scan.state)
        self.assertEqual(1, len(self.session.scalars(select(AuditEvent)).all()))
        self.assertEqual(1, len(self.session.scalars(select(OutboxEvent)).all()))

    def test_cross_organization_transition_is_denied(self):
        from control_plane.scans import ScanNotFound, transition_scan
        from control_plane.models import ScanState

        with self.assertRaises(ScanNotFound):
            transition_scan(self.session, self.scan.id, self.other_org.id, self.user.id, ScanState.UPLOADED, "k")

    def test_terminal_scan_cannot_restart(self):
        from control_plane.models import ScanState
        from control_plane.scans import InvalidTransition, transition_scan

        self.scan.state = ScanState.COMPLETED
        self.session.commit()
        with self.assertRaises(InvalidTransition):
            transition_scan(self.session, self.scan.id, self.org.id, self.user.id, ScanState.STATIC, "restart")

    def test_dynamic_transition_requires_release_gate(self):
        from control_plane.models import ScanState
        from control_plane.scans import NotAuthorized, transition_scan

        self.scan.state = ScanState.DYNAMIC_ELIGIBLE
        self.scan.dynamic_authorized = True
        self.session.commit()
        with self.assertRaisesRegex(NotAuthorized, "release gate"):
            transition_scan(self.session, self.scan.id, self.org.id, self.user.id, ScanState.VALIDATING, "validate")

    def test_outbox_claim_and_ack(self):
        from control_plane.models import ScanState
        from control_plane.outbox import claim_outbox, mark_delivered
        from control_plane.scans import transition_scan

        transition_scan(self.session, self.scan.id, self.org.id, self.user.id, ScanState.UPLOADED, "upload")
        claimed = claim_outbox(self.session, limit=10)
        self.assertEqual(1, len(claimed))
        self.assertEqual(1, claimed[0].attempts)
        mark_delivered(self.session, claimed[0].id)
        self.session.commit()
        self.assertEqual([], claim_outbox(self.session, limit=10))

    def test_outbox_dispatch_retries_failure_and_sends_identifiers_only(self):
        from control_plane.models import OutboxEvent
        from control_plane.outbox import dispatch_once

        event = OutboxEvent(
            organization_id=self.org.id, scan_id=self.scan.id,
            kind="scan.queue", payload={"source": "must-stay-in-database"},
        )
        self.session.add(event)
        self.session.commit()

        def fail(_message):
            raise RuntimeError("receiver unavailable")

        with self.assertRaisesRegex(RuntimeError, "receiver unavailable"):
            dispatch_once(self.engine, fail)
        self.session.expire_all()
        self.assertIsNone(self.session.get(OutboxEvent, event.id).delivered_at)

        delivered = []
        self.assertTrue(dispatch_once(self.engine, delivered.append))
        self.assertEqual(1, len(delivered))
        self.assertEqual(event.id, delivered[0].event_id)
        self.assertEqual(self.org.id, delivered[0].organization_id)
        self.assertFalse(hasattr(delivered[0], "payload"))
        self.assertFalse(dispatch_once(self.engine, delivered.append))
        self.session.expire_all()
        self.assertIsNotNone(self.session.get(OutboxEvent, event.id).delivered_at)

    def test_visible_events_have_monotonic_sequence_and_redacted_summary(self):
        from control_plane.events import append_visible_event

        first = append_visible_event(self.session, self.scan.id, self.org.id, "intake", "Started")
        second = append_visible_event(self.session, self.scan.id, self.org.id, "scanner", "token=supersecret")
        self.assertEqual((1, 2), (first.sequence, second.sequence))
        self.assertNotIn("supersecret", second.summary)
        self.assertIn("[REDACTED]", second.summary)

    def test_grant_checks_binding_expiry_and_revocation(self):
        from control_plane.grants import GrantError, issue_grant, recover_grant_token, verify_grant
        from control_plane.models import ScanState

        now = datetime(2026, 10, 3, tzinfo=timezone.utc)
        key = b"k" * 32
        with self.assertRaisesRegex(GrantError, "authorized"):
            issue_grant(self.session, self.scan, key, timedelta(minutes=5), now=now)
        self.scan.state = ScanState.AUTHORIZED
        self.session.flush()
        token = issue_grant(self.session, self.scan, key, timedelta(minutes=5), now=now)
        claims = verify_grant(self.session, token, key, self.scan.source_digest, now=now + timedelta(seconds=1))
        self.assertEqual(self.scan.id, claims.scan_id)
        self.assertEqual(token, recover_grant_token(self.session, claims.record.id, key, now=now))
        with self.assertRaisesRegex(GrantError, "source digest"):
            verify_grant(self.session, token, key, "different", now=now)
        with self.assertRaisesRegex(GrantError, "expired"):
            verify_grant(self.session, token, key, self.scan.source_digest, now=now + timedelta(minutes=6))
        claims.record.revoked_at = now + timedelta(seconds=2)
        self.session.flush()
        with self.assertRaisesRegex(GrantError, "revoked"):
            verify_grant(self.session, token, key, self.scan.source_digest, now=now + timedelta(seconds=3))


if __name__ == "__main__":
    unittest.main()
