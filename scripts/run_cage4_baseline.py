#!/usr/bin/env python3
"""Run pinned CAGE 4 substrate baselines without the full RL dependency stack."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ordivon_security_experiments.cage4 import (  # noqa: E402
    CAGE4_REVISION,
    Cage4BaselineSpec,
    run_cage4_baselines,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT / ".cache" / "cage4")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", default="1,2,3")
    parser.add_argument("--steps", type=int, default=30)
    parser.add_argument("--blue-policies", default="sleep,random")
    parser.add_argument("--red-policies", default="finite-state,random-select")
    args = parser.parse_args()

    spec = Cage4BaselineSpec(
        experiment_id="EXP-001-cage4-substrate-comparison",
        source_path=str(args.source.resolve()),
        source_revision=CAGE4_REVISION,
        seeds=tuple(int(value) for value in args.seeds.split(",") if value),
        steps=args.steps,
        blue_policies=tuple(value for value in args.blue_policies.split(",") if value),
        red_policies=tuple(value for value in args.red_policies.split(",") if value),
    )
    summary = run_cage4_baselines(spec, args.output)
    print(f"trials={summary['trial_count']}")
    print(f"summary={args.output / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
