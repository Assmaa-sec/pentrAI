"""
Command-line entry point — the way to drive the pipeline until the web front-end
exists (the front-end is deliberately last).

    python -m pentrai_pipeline ./path/to/repo
    python -m pentrai_pipeline https://github.com/acme/app.git --authorized
    python -m pentrai_pipeline ./app --posture authenticated --secrets ./creds.env
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import Settings
from .contracts import Posture, SourceKind, Target


def _classify_source(ref: str) -> SourceKind:
    if ref.endswith(".git") or ref.startswith(("http://", "https://", "git@")):
        return SourceKind.GIT
    if ref.lower().endswith(".zip"):
        return SourceKind.ZIP
    return SourceKind.FOLDER


def build_target(args: argparse.Namespace) -> Target:
    return Target(
        source_ref=args.source,
        kind=_classify_source(args.source),
        posture=Posture(args.posture),
        secrets_path=args.secrets,
        authorized=args.authorized,
        scope_note=args.scope or "",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pentrai_pipeline",
        description="Analyze + live-attack a codebase in an isolated sandbox, then report.",
    )
    parser.add_argument("source", help="folder path, .zip path, or git URL of the target codebase")
    parser.add_argument(
        "--posture",
        choices=[p.value for p in Posture],
        default=Posture.EXTERNAL.value,
        help="external (default, no secrets) or authenticated (deeper, needs --secrets)",
    )
    parser.add_argument("--secrets", help="path to creds/config, only used in --posture authenticated")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="attest you are authorized to test this code (required to run)",
    )
    parser.add_argument("--scope", help="free-text note on the authorized scope")
    parser.add_argument("--json", action="store_true", help="print the PipelineResult as JSON")
    args = parser.parse_args(argv)

    if args.posture == Posture.AUTHENTICATED.value and not args.secrets:
        parser.error("--posture authenticated requires --secrets PATH")

    settings = Settings.from_env()
    target = build_target(args)

    # Imported here so `--help` works even before the stages are implemented.
    from .orchestrator import run_pipeline

    result = run_pipeline(target, settings)

    if args.json:
        from .serialization import pipeline_result_dict

        print(json.dumps(pipeline_result_dict(result), ensure_ascii=False))
        return 0

    # Reporting of the run is intentionally minimal until stages are implemented.
    print(f"[pentrai-pipeline] target={target.source_ref} posture={target.posture.value}")
    print(f"[pentrai-pipeline] findings={len(result.findings)} validated={len(result.validated)} reports={len(result.reports)}")
    for rep in result.reports:
        print(f"  - {rep.audience.value} report: {rep.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
