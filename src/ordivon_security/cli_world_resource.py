from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject
from ordivon_security.world_boundary import (
    WorldResourceInbox,
    WorldResourceRequestError,
    rejected_world_resource_response,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Admit or reconcile one digest-bound Ordivon World Resource Transfer "
            "against a Security-owned SampleVault destination. JSON request is read from stdin. "
            "The CLI treats its local caller as the source-authority trust boundary; "
            "untrusted-relay "
            "deployments must verify Resource Egress authority independently before invocation."
        )
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--destination-world-id", required=True)
    parser.add_argument("--allow-source-world", action="append", default=[])
    parser.add_argument("--allow-resource-kind", action="append", default=[])
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raw = json.load(sys.stdin)
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise SystemExit("World Resource request must be a JSON object")
    inbox = WorldResourceInbox(
        args.root,
        destination_world_id=args.destination_world_id,
        allowed_source_world_ids=tuple(args.allow_source_world),
        allowed_resource_kinds=tuple(args.allow_resource_kind),
    )
    try:
        response = inbox.handle(cast(JsonObject, raw))
    except WorldResourceRequestError as error:
        response = rejected_world_resource_response(error)
    print(json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
