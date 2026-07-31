#!/usr/bin/env python3
"""Generate the Security R-A adversarial control-boundary evidence report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ordivon_security_evaluations.control_boundary import (  # noqa: E402
    evaluate,
    load_game_report,
    report_markdown,
)

DEFAULT_SOURCE = (
    ROOT
    / "fixtures"
    / "adversarial-control-boundary"
    / "game-m5-r1-control-boundary.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--game-main-revision", required=True)
    parser.add_argument("--security-source-revision", required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = evaluate(
        load_game_report(args.source),
        game_main_revision=args.game_main_revision,
        security_source_revision=args.security_source_revision,
    )
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.markdown_output.write_text(report_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
