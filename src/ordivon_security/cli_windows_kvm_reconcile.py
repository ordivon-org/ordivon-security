from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation.windows_kvm_reconcile import reconcile_windows_kvm_runs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reconcile orphaned Windows KVM Run state after a hard process or Runtime failure."
        )
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--diagnostics-root", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = reconcile_windows_kvm_runs(
        args.state_root,
        receipt_path=args.receipt,
        diagnostics_root=args.diagnostics_root,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    if result["status"] != "passed":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
