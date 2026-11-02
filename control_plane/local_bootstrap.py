"""Explicit loopback development identity bootstrap. Never used by deployed auth."""

from __future__ import annotations

import argparse
import time

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from .auth import mint_local_token
from .models import Membership, Organization, OrganizationCreditAccount, Project, User
from .credits import grant_credits
from .settings import Settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision a local development workspace")
    parser.add_argument("--organization", default="Local workspace")
    parser.add_argument("--project", default="My project")
    parser.add_argument("--subject", default="local-owner")
    args = parser.parse_args()
    settings = Settings.from_env()
    if not settings.local_dev_auth:
        parser.error("set PENTRAI_LOCAL_DEV_AUTH=true explicitly")
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        organization = session.scalar(select(Organization).where(Organization.name == args.organization))
        if organization is None:
            organization = Organization(name=args.organization)
            session.add(organization)
            session.flush()
        subject = f"urn:pentrai:local|{args.subject}"
        user = session.scalar(select(User).where(User.oidc_subject == subject))
        if user is None:
            user = User(oidc_subject=subject)
            session.add(user)
            session.flush()
        membership = session.scalar(select(Membership).where(
            Membership.organization_id == organization.id, Membership.user_id == user.id,
        ))
        if membership is None:
            session.add(Membership(organization_id=organization.id, user_id=user.id, role="owner"))
        project = session.scalar(select(Project).where(
            Project.organization_id == organization.id, Project.name == args.project,
        ))
        if project is None:
            project = Project(organization_id=organization.id, name=args.project)
            session.add(project)
        if session.get(OrganizationCreditAccount, organization.id) is None:
            grant_credits(session, organization.id, 1_000_000,
                          actor_id=user.id, reason="local development allocation")
        session.commit()
        print(f"Organization ID: {organization.id}")
        print(f"Project ID: {project.id}")
        print("Bearer token (expires in 24 hours):")
        print(mint_local_token(args.subject, settings.grant_signing_key.get_secret_value().encode(), int(time.time()) + 86400))


if __name__ == "__main__":
    main()
