from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation.windows_kvm_p1 import (
    reconcile_windows_kvm_p1_non_executable_media,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Remove only manifest-verified P1 media with no evaluation authority."
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipts-root", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    receipts = reconcile_windows_kvm_p1_non_executable_media(
        args.state_root,
        args.receipts_root,
    )
    print(json.dumps(list(receipts), ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
