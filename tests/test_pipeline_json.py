from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest.mock import patch

from pentrai_pipeline.contracts import (
    Audience,
    Finding,
    FindingSource,
    PipelineResult,
    Posture,
    Report,
    Severity,
    SourceKind,
    Target,
)


class PipelineJsonTests(unittest.TestCase):
    def test_versioned_result_serializes_nested_contracts_without_secret_path(self):
        from pentrai_pipeline.serialization import pipeline_result_dict

        target = Target(
            source_ref="sample.zip",
            kind=SourceKind.ZIP,
            posture=Posture.AUTHENTICATED,
            secrets_path="C:/private/credentials.env",
            authorized=True,
        )
        result = PipelineResult(target=target)
        result.findings.append(Finding("Example", FindingSource.SAST, severity=Severity.HIGH))
        result.reports.append(Report(Audience.CLIENT, "Summary", "Test body"))

        payload = pipeline_result_dict(result)
        encoded = json.dumps(payload)

        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("zip", payload["result"]["target"]["kind"])
        self.assertEqual("high", payload["result"]["findings"][0]["severity"])
        self.assertEqual("client", payload["result"]["reports"][0]["audience"])
        self.assertIn("+00:00", payload["result"]["target"]["created_at"])
        self.assertNotIn("secrets_path", encoded)
        self.assertNotIn("credentials.env", encoded)

    def test_cli_json_emits_only_valid_json(self):
        from pentrai_pipeline.cli import main

        output = io.StringIO()
        with patch("pentrai_pipeline.orchestrator.run_pipeline", side_effect=lambda target, settings: PipelineResult(target)):
            with contextlib.redirect_stdout(output):
                code = main(["sample.zip", "--authorized", "--json"])

        self.assertEqual(0, code)
        payload = json.loads(output.getvalue())
        self.assertEqual("sample.zip", payload["result"]["target"]["source_ref"])
        self.assertEqual(1, payload["schema_version"])


if __name__ == "__main__":
    unittest.main()
