#!/usr/bin/env python3
"""Verify and inspect one Security Campaign ledger without mutation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ordivon_security_contracts import CampaignLedger, ContractError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--events", action="store_true", help="include verified events")
    arguments = parser.parse_args()
    try:
        ledger = CampaignLedger(arguments.ledger)
        payload = {"projection": ledger.projection().to_dict()}
        if arguments.events:
            payload["events"] = [event.to_dict() for event in ledger.events()]
    except (ContractError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
