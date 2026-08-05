from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation import audit_quarantine_tree, write_quarantine_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only audit of quarantine permissions, executable files, links, and "
            "special entries."
        )
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit with status 2 when the quarantine tree is not compliant.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.receipt is None:
        audit = audit_quarantine_tree(args.root)
    else:
        audit = write_quarantine_audit(args.root, args.receipt)
    print(json.dumps(audit, ensure_ascii=False, sort_keys=True, indent=2))
    if args.fail_on_violation and audit.get("compliant") is not True:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
