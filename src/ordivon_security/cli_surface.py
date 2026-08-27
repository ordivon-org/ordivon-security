from __future__ import annotations

import argparse
import json

from .ordinary_capability import security_ordinary_capability_preflight
from .surface import security_ordinary_surface_manifest, security_surface_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ordivon-security-surface",
        description=(
            "Project the current Security Agent-facing surface taxonomy "
            "without running an experiment."
        ),
    )
    parser.add_argument(
        "--view",
        choices=("full", "ordinary"),
        default="ordinary",
        help="project the ordinary task view by default or the explicit full maturity surface",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="project owner-local mechanical eligibility for ordinary model-facing operations",
    )
    parser.add_argument(
        "--record-id",
        help="exact current owner-memory recordId selected by a prior ordinary query",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="emit canonical compact JSON instead of indented JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.record_id is not None and not args.preflight:
        raise SystemExit("--record-id requires --preflight")
    if args.preflight:
        if args.view != "ordinary":
            raise SystemExit("--preflight is valid only for --view ordinary")
        value = security_ordinary_capability_preflight(record_id=args.record_id)
    else:
        value = (
            security_ordinary_surface_manifest()
            if args.view == "ordinary"
            else security_surface_manifest()
        )
    if args.compact:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
