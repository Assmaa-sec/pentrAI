import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from control_plane.hexstrike_findings import persist_finding_drafts
from control_plane.models import Base, Organization, Project, Scan, ScanFinding, ScanState
from pentrai_pipeline.agents.hexstrike_findings import FindingDraft


class PersistHexStrikeFindingTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as session:
            session.add(Organization(id="org", name="Organization"))
            session.add(Project(id="project", organization_id="org", name="Project"))
            session.add(Scan(id="scan", organization_id="org", project_id="project",
                             source_digest="a" * 64, scope_digest="b" * 64,
                             profile="standard", state=ScanState.STATIC))
            session.commit()

    def tearDown(self):
        self.engine.dispose()

    def test_persists_model_explanation_once(self):
        draft = FindingDraft("Possible issue", "medium", "Model explanation", ("c" * 64,))
        with Session(self.engine) as session:
            self.assertEqual(persist_finding_drafts(session, "org", "scan", [draft]), 1)
            session.commit()
            self.assertEqual(persist_finding_drafts(session, "org", "scan", [draft]), 0)
            finding = session.scalar(select(ScanFinding).where(ScanFinding.scan_id == "scan"))
            self.assertEqual(finding.explanation, "Model explanation")
            self.assertEqual(finding.evidence_sha256, ["c" * 64])

    def test_rejects_wrong_organization(self):
        with Session(self.engine) as session:
            with self.assertRaises(PermissionError):
                persist_finding_drafts(session, "other", "scan", [])
