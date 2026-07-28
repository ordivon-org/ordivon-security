#!/usr/bin/env python3
"""Verify a sealed Security Campaign evidence bundle and replay its ledger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ordivon_security_contracts import ContractError, verify_evidence_bundle  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    arguments = parser.parse_args()
    try:
        receipt = verify_evidence_bundle(arguments.bundle)
    except (ContractError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
