from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation import (
    CaseExecutionStatus,
    create_case_snapshot,
    verify_case_snapshot,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a digest-bound metadata snapshot of an evolving local security Case. "
            "Sample and artifact bytes are not copied."
        )
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument(
        "--execution-status",
        required=True,
        choices=tuple(status.value for status in CaseExecutionStatus),
    )
    parser.add_argument("--source-run", action="append", default=[])
    parser.add_argument("--limitation", action="append", default=[])
    return parser


def main() -> None:
    args = build_parser().parse_args()
    bundle = create_case_snapshot(
        args.root,
        args.output,
        case_id=args.case_id,
        execution_status=CaseExecutionStatus(args.execution_status),
        source_evaluation_run_ids=tuple(args.source_run),
        limitations=tuple(args.limitation),
    )
    verified_digest = verify_case_snapshot(bundle.path)
    if verified_digest != bundle.manifest_digest:
        raise RuntimeError("Case snapshot verification returned another digest")
    print(json.dumps(bundle.to_dict(), ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
