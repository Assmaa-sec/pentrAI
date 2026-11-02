from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from control_plane.grants import issue_grant, verify_grant
from control_plane.credits import grant_credits, reserve_scan_credits
from control_plane.model_gateway import create_model_gateway
from control_plane.model_catalog import ModelOption
from control_plane.models import Base, Organization, OrganizationCreditAccount, Project, Scan, ScanCreditReservation, ScanState
from execution_manager.leases import create_lease
from execution_manager.model_tokens import ModelTokenRejected, mint_model_token, verify_model_token


class ModelGatewayTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool,
                                    connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        organization = Organization(name="Owned model fixture")
        self.session.add(organization)
        self.session.flush()
        project = Project(organization_id=organization.id, name="Gateway")
        self.session.add(project)
        self.session.flush()
        self.scan = Scan(organization_id=organization.id, project_id=project.id,
                         source_digest="a" * 64, scope_digest="b" * 64,
                         profile="quick", dynamic_authorized=False,
                         state=ScanState.QUEUED)
        self.session.add(self.scan)
        self.session.flush()
        self.key = b"g" * 32
        self.now = datetime.now(timezone.utc)
        grant = issue_grant(self.session, self.scan, self.key,
                            timedelta(minutes=5), now=self.now)
        claims = verify_grant(self.session, grant, self.key, self.scan.source_digest,
                              now=self.now)
        self.lease = create_lease(self.session, claims, timedelta(minutes=5), now=self.now)
        self.token = mint_model_token(self.lease, self.key, now=self.now)
        self.session.commit()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_token_is_lease_bound_and_revocation_stops_model_access(self):
        self.assertEqual(self.lease.id,
                         verify_model_token(self.session, self.token, self.key,
                                            now=self.now).id)
        with self.assertRaises(ModelTokenRejected):
            verify_model_token(self.session, self.token, b"wrong-key" * 4,
                               now=self.now)
        with self.assertRaises(ModelTokenRejected):
            verify_model_token(self.session, self.token, self.key,
                               now=self.now + timedelta(minutes=6))
        self.lease.cleaned_at = self.now + timedelta(seconds=1)
        self.session.flush()
        with self.assertRaises(ModelTokenRejected):
            verify_model_token(self.session, self.token, self.key,
                               now=self.now + timedelta(seconds=2))

    def test_private_gateway_proxies_scoped_request_without_provider_key_in_runner(self):
        forwarded = []

        def respond(request: httpx.Request) -> httpx.Response:
            forwarded.append(request)
            self.assertEqual("Bearer provider-secret", request.headers["authorization"])
            self.assertEqual("provider-model", json.loads(request.content)["model"])
            return httpx.Response(200, json={
                "choices": [{"message": {"role": "assistant", "content": "review complete"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
            })

        app = create_model_gateway(
            self.engine, self.key, "https://provider.example/v1",
            "provider-secret", "provider-model", transport=httpx.MockTransport(respond),
        )
        client = TestClient(app)
        payload = {"model": "managed", "messages": [{"role": "user", "content": "fixture"}]}
        self.assertEqual(403, client.post("/v1/chat/completions", json=payload).status_code)
        response = client.post("/v1/chat/completions", json=payload,
                               headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(200, response.status_code)
        self.assertEqual("review complete", response.json()["choices"][0]["message"]["content"])
        self.assertEqual(1, len(forwarded))
        self.assertNotIn("provider-secret", str(response.json()))
        self.session.get(self.lease.__class__, self.lease.id).cleaned_at = self.now
        self.session.commit()
        self.assertEqual(403, client.post("/v1/chat/completions", json=payload,
                                          headers={"Authorization": f"Bearer {self.token}"}).status_code)
        self.assertEqual(1, len(forwarded))

    def test_gateway_bounds_upstream_response_and_hides_error_body(self):
        transport = httpx.MockTransport(lambda request: httpx.Response(
            200, content=b"sensitive" + b"x" * (2 * 1024 * 1024)))
        app = create_model_gateway(self.engine, self.key,
                                   "https://provider.example/v1", "provider-secret",
                                   "provider-model", transport=transport)
        response = TestClient(app).post(
            "/v1/chat/completions",
            json={"model": "managed", "messages": [{"role": "user", "content": "fixture"}]},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(502, response.status_code)
        self.assertNotIn("sensitive", response.text)

    def test_gateway_meters_provider_usage_against_scan_reservation(self):
        grant_credits(self.session, self.scan.organization_id, 20_000,
                      actor_id="fixture-owner", reason="owned test allocation")
        reserve_scan_credits(self.session, self.scan)
        self.session.commit()

        def respond(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "choices": [{"message": {"role": "assistant", "content": "review complete"}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
            })

        app = create_model_gateway(self.engine, self.key, "https://provider.example/v1",
                                   "provider-secret", "provider-model",
                                   transport=httpx.MockTransport(respond))
        response = TestClient(app).post(
            "/v1/chat/completions",
            json={"model": "managed", "messages": [{"role": "user", "content": "fixture"}]},
            headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(200, response.status_code, response.text)
        self.session.expire_all()
        reservation = self.session.get(ScanCreditReservation, self.scan.id)
        self.assertEqual(12, reservation.metered_credits)
        account = self.session.get(OrganizationCreditAccount, self.scan.organization_id)
        self.assertEqual((0, 20_000, 0), (account.available, account.reserved, account.spent))

    def test_gateway_routes_selected_option_and_uses_its_metered_rates(self):
        self.scan.model_id = "deep"
        self.scan.prompt_credit_rate = 2
        self.scan.completion_credit_rate = 4
        grant_credits(self.session, self.scan.organization_id, 80_000,
                      actor_id="fixture-owner", reason="owned test allocation")
        reserve_scan_credits(self.session, self.scan)
        self.session.commit()
        option = ModelOption("deep", "Deep model", "deep-provider",
                             "https://deep.example/v1", "PENTRAI_DEEP_TEST_KEY", 2, 4)

        def respond(request: httpx.Request) -> httpx.Response:
            self.assertEqual("deep.example", request.url.host)
            self.assertEqual("Bearer deep-secret", request.headers["authorization"])
            self.assertEqual("deep-provider", json.loads(request.content)["model"])
            return httpx.Response(200, json={
                "choices": [{"message": {"role": "assistant", "content": "review"}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
            })

        with patch.dict(os.environ, {"PENTRAI_DEEP_TEST_KEY": "deep-secret"}):
            app = create_model_gateway(self.engine, self.key,
                catalog={"deep": option}, transport=httpx.MockTransport(respond))
            response = TestClient(app).post("/v1/chat/completions",
                json={"model": "managed", "messages": [{"role": "user", "content": "fixture"}]},
                headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(200, response.status_code, response.text)
        self.session.expire_all()
        reservation = self.session.get(ScanCreditReservation, self.scan.id)
        self.assertEqual(34, reservation.metered_credits)


if __name__ == "__main__":
    unittest.main()
