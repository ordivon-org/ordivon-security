from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject
from ordivon_security.world_boundary import (
    WorldMessageInbox,
    WorldMessageRequestError,
    rejected_world_message_response,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Admit or reconcile one source-issued Ordivon World Message against a Security-owned "
            "durable inbox. JSON request is read from stdin. Delivery is management-classified "
            "and never promotes destination knowledge or world-truth. The CLI trusts its local "
            "caller for source-authority authentication; untrusted relays must authenticate "
            "Message Issuance authority independently before invocation."
        )
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--destination-world-id", required=True)
    parser.add_argument("--allow-source-world", action="append", default=[])
    parser.add_argument("--allow-message-kind", action="append", default=[])
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raw = json.load(sys.stdin)
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise SystemExit("World Message request must be a JSON object")
    inbox = WorldMessageInbox(
        args.root,
        destination_world_id=args.destination_world_id,
        allowed_source_world_ids=tuple(args.allow_source_world),
        allowed_message_kinds=tuple(args.allow_message_kind),
    )
    try:
        response = inbox.handle(cast(JsonObject, raw))
    except WorldMessageRequestError as error:
        response = rejected_world_message_response(error)
    print(json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
