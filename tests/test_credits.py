"""Credit invariants: reserve once, charge usage, refund or release exactly once."""

from __future__ import annotations

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from control_plane.credits import (CreditRejected, grant_credits, release_scan_credits,
                                   reserve_scan_credits, settle_scan_credits,
                                   record_model_usage)
from control_plane.models import (Base, Organization, OrganizationCreditAccount,
                                  Project, Scan, User)


class CreditLedgerTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool,
                                    connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        org = Organization(name="Owned credits fixture")
        user = User(oidc_subject="owned-credits-user")
        self.session.add_all([org, user])
        self.session.flush()
        project = Project(organization_id=org.id, name="One")
        self.session.add(project)
        self.session.flush()
        self.scan = Scan(organization_id=org.id, project_id=project.id,
                         source_digest="a" * 64, scope_digest="b" * 64,
                         profile="quick", execution_backend="hexstrike")
        self.session.add(self.scan)
        self.session.flush()
        self.org_id = org.id
        self.user_id = user.id

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_reserve_settle_and_retry_are_idempotent(self):
        grant_credits(self.session, self.org_id, 25_000,
                      actor_id=self.user_id, reason="owned test allocation")
        reservation = reserve_scan_credits(self.session, self.scan)
        self.assertEqual(reservation.scan_id, reserve_scan_credits(self.session, self.scan).scan_id)
        account = self.session.get(OrganizationCreditAccount, self.org_id)
        self.assertEqual((5000, 20000, 0), (account.available, account.reserved, account.spent))
        self.assertEqual(35, record_model_usage(self.session, self.scan.id,
                         {"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35}))
        self.assertEqual(35, settle_scan_credits(self.session, self.scan,
                         {"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35}))
        self.assertEqual(35, settle_scan_credits(self.session, self.scan,
                         {"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35}))
        self.assertEqual(0, release_scan_credits(self.session, self.scan))
        self.assertEqual((24965, 0, 35), (account.available, account.reserved, account.spent))
        with self.assertRaises(CreditRejected):
            settle_scan_credits(self.session, self.scan,
                                {"prompt_tokens": 20, "completion_tokens": 16})

    def test_failure_releases_and_insufficient_balance_rejects(self):
        with self.assertRaises(CreditRejected):
            reserve_scan_credits(self.session, self.scan)
        grant_credits(self.session, self.org_id, 20_000,
                      actor_id=self.user_id, reason="owned test allocation")
        reserve_scan_credits(self.session, self.scan)
        record_model_usage(self.session, self.scan.id,
                           {"prompt_tokens": 120, "completion_tokens": 30})
        self.assertEqual(19_850, release_scan_credits(self.session, self.scan))
        self.assertEqual(0, release_scan_credits(self.session, self.scan))
        account = self.session.get(OrganizationCreditAccount, self.org_id)
        self.assertEqual((19_850, 0, 150), (account.available, account.reserved, account.spent))

    def test_late_provider_usage_after_cancel_is_still_charged(self):
        grant_credits(self.session, self.org_id, 20_000,
                      actor_id=self.user_id, reason="owned test allocation")
        reserve_scan_credits(self.session, self.scan)
        self.assertEqual(20_000, release_scan_credits(self.session, self.scan))
        record_model_usage(self.session, self.scan.id,
                           {"prompt_tokens": 8, "completion_tokens": 2})
        account = self.session.get(OrganizationCreditAccount, self.org_id)
        self.assertEqual((19_990, 0, 10), (account.available, account.reserved, account.spent))

    def test_provider_must_report_nonzero_token_usage(self):
        grant_credits(self.session, self.org_id, 20_000,
                      actor_id=self.user_id, reason="owned test allocation")
        reserve_scan_credits(self.session, self.scan)
        for usage in ({}, {"prompt_tokens": 1}, {"total_tokens": 0}):
            with self.subTest(usage=usage), self.assertRaises(CreditRejected):
                record_model_usage(self.session, self.scan.id, usage)
        account = self.session.get(OrganizationCreditAccount, self.org_id)
        self.assertEqual((0, 20_000, 0),
                         (account.available, account.reserved, account.spent))

    def test_selected_model_rates_charge_prompt_and_completion_separately(self):
        self.scan.model_id = "premium"
        self.scan.prompt_credit_rate = 2
        self.scan.completion_credit_rate = 3
        grant_credits(self.session, self.org_id, 100_000,
                      actor_id=self.user_id, reason="owned test allocation")
        reservation = reserve_scan_credits(self.session, self.scan)
        self.assertEqual(60_000, reservation.reserved_credits)
        usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        self.assertEqual(35, record_model_usage(self.session, self.scan.id, usage))
        self.assertEqual(35, settle_scan_credits(self.session, self.scan, usage))
        account = self.session.get(OrganizationCreditAccount, self.org_id)
        self.assertEqual((99_965, 0, 35),
                         (account.available, account.reserved, account.spent))


if __name__ == "__main__":
    unittest.main()
