from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation import harden_quarantine_tree


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Apply owner-only non-executable permissions to a quarantine tree."
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    receipt = harden_quarantine_tree(args.root, receipt_path=args.receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
