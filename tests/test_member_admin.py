"""Member administration respects roles, tenant boundaries, and last-owner safety."""

from __future__ import annotations

import shutil
import time
import unittest
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from control_plane.app import create_app
from control_plane.auth import mint_local_token
from control_plane.models import AuditEvent, Base, Membership, Organization, User
from control_plane.settings import Settings


class MemberAdminTests(unittest.TestCase):
    def test_local_session_requires_explicit_mode_and_allowed_origin(self):
        root = Path('.tmp/local-session-e2e') / uuid.uuid4().hex
        root.mkdir(parents=True)
        database_url = f"sqlite+pysqlite:///{(root / 'control.db').as_posix()}"
        engine = create_engine(database_url)
        clients = []
        try:
            Base.metadata.create_all(engine)
            with Session(engine) as session:
                org = Organization(name='Local workspace')
                owner = User(oidc_subject='urn:pentrai:local|local-owner')
                session.add_all([org, owner])
                session.flush()
                session.add(Membership(organization_id=org.id, user_id=owner.id, role='owner'))
                session.commit()
                org_id = org.id
            signing_key = 'local-session-signing-key-32-bytes-minimum'
            disabled = TestClient(create_app(Settings(
                database_url=database_url, grant_signing_key=signing_key, local_dev_auth=False,
            )))
            enabled = TestClient(create_app(Settings(
                database_url=database_url, grant_signing_key=signing_key, local_dev_auth=True,
            )))
            clients.extend([disabled, enabled])
            self.assertEqual(404, disabled.post('/v1/local/session').status_code)
            self.assertEqual(403, enabled.post('/v1/local/session', headers={
                'Origin': 'https://untrusted.example',
            }).status_code)
            response = enabled.post('/v1/local/session', headers={
                'Origin': 'http://127.0.0.1:5173',
            })
            self.assertEqual(200, response.status_code, response.text)
            self.assertEqual('no-store', response.headers['cache-control'])
            self.assertEqual(org_id, response.json()['organization_id'])
            token = response.json()['token']
            self.assertEqual(200, enabled.get(f'/v1/organizations/{org_id}/access', headers={
                'Authorization': f'Bearer {token}',
            }).status_code)
        finally:
            for client in clients:
                client.close()
                client.app.state.engine.dispose()
            engine.dispose()
            shutil.rmtree(root)

    def test_owner_changes_role_and_revokes_member_with_tenant_checks(self):
        root = Path('.tmp/member-admin-e2e') / uuid.uuid4().hex
        root.mkdir(parents=True)
        database_url = f"sqlite+pysqlite:///{(root / 'control.db').as_posix()}"
        engine = create_engine(database_url)
        client = None
        try:
            Base.metadata.create_all(engine)
            with Session(engine) as session:
                org, other = Organization(name='Main'), Organization(name='Other')
                owner = User(oidc_subject='urn:pentrai:local|admin-owner')
                developer = User(oidc_subject='urn:pentrai:local|admin-developer')
                outsider = User(oidc_subject='urn:pentrai:local|admin-outsider')
                session.add_all([org, other, owner, developer, outsider])
                session.flush()
                owner_member = Membership(organization_id=org.id, user_id=owner.id, role='owner')
                developer_member = Membership(organization_id=org.id, user_id=developer.id, role='developer')
                outsider_member = Membership(organization_id=other.id, user_id=outsider.id, role='owner')
                session.add_all([owner_member, developer_member, outsider_member])
                session.commit()
                org_id, other_id = org.id, other.id
                owner_member_id, developer_member_id = owner_member.id, developer_member.id
                outsider_member_id = outsider_member.id

            signing_key = b'local-member-admin-signing-key-32-bytes'
            client = TestClient(create_app(Settings(
                database_url=database_url, grant_signing_key=signing_key.decode(), local_dev_auth=True,
            )))
            def headers(subject):
                token = mint_local_token(subject, signing_key, int(time.time()) + 300)
                return {'Authorization': f'Bearer {token}'}

            prefix = f'/v1/organizations/{org_id}'
            owner_headers = headers('admin-owner')
            developer_headers = headers('admin-developer')
            self.assertEqual(200, client.get(f'{prefix}/access', headers=developer_headers).status_code)
            self.assertEqual(403, client.get(f'{prefix}/members', headers=developer_headers).status_code)
            self.assertEqual(403, client.get(f'{prefix}/audit-events', headers=developer_headers).status_code)
            self.assertEqual(404, client.get(f'{prefix}/members', headers=headers('admin-outsider')).status_code)
            listed = client.get(f'{prefix}/members', headers=owner_headers)
            self.assertEqual(200, listed.status_code)
            self.assertEqual(2, len(listed.json()))
            self.assertEqual(404, client.patch(
                f'{prefix}/members/{outsider_member_id}', json={'role': 'developer'},
                headers=owner_headers,
            ).status_code)
            self.assertEqual(409, client.patch(
                f'{prefix}/members/{owner_member_id}', json={'role': 'developer'},
                headers=owner_headers,
            ).status_code)
            self.assertEqual(409, client.delete(
                f'{prefix}/members/{owner_member_id}', headers=owner_headers,
            ).status_code)
            changed = client.patch(
                f'{prefix}/members/{developer_member_id}',
                json={'role': 'security_engineer'}, headers=owner_headers,
            )
            self.assertEqual(200, changed.status_code, changed.text)
            self.assertEqual('security_engineer', changed.json()['role'])
            self.assertEqual(403, client.delete(
                f'{prefix}/members/{developer_member_id}', headers=developer_headers,
            ).status_code)
            self.assertEqual(204, client.delete(
                f'{prefix}/members/{developer_member_id}', headers=owner_headers,
            ).status_code)
            self.assertEqual(404, client.get(f'{prefix}/access', headers=developer_headers).status_code)
            self.assertEqual(404, client.get(
                f'/v1/organizations/{other_id}/members', headers=owner_headers,
            ).status_code)
            audit = client.get(f'{prefix}/audit-events', headers=owner_headers)
            self.assertEqual(200, audit.status_code)
            self.assertIn('member.remove', [entry['action'] for entry in audit.json()])
            with Session(engine) as session:
                actions = session.scalars(select(AuditEvent.action).where(
                    AuditEvent.organization_id == org_id,
                )).all()
                self.assertIn('member.role_change', actions)
                self.assertIn('member.remove', actions)
        finally:
            if client is not None:
                client.close()
                client.app.state.engine.dispose()
            engine.dispose()
            shutil.rmtree(root)


if __name__ == '__main__':
    unittest.main()
