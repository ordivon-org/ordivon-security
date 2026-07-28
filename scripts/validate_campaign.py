#!/usr/bin/env python3
"""Validate and fingerprint an Ordivon Security Campaign Manifest v0."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ordivon_security_contracts.campaign import (  # noqa: E402
    ContractError,
    canonical_bytes,
    load_json,
    manifest_digest,
    validate_campaign,
    validate_transition,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="Campaign Manifest JSON path")
    parser.add_argument("--previous", help="prior admitted revision to compare")
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--canonical", action="store_true", help="write canonical JSON to stdout"
    )
    output.add_argument(
        "--digest", action="store_true", help="write the computed manifest digest"
    )
    args = parser.parse_args()

    try:
        manifest = load_json(args.manifest)
        if args.previous:
            validate_transition(load_json(args.previous), manifest)
        else:
            validate_campaign(manifest)
    except ContractError as exc:
        for error in exc.errors:
            print(f"ERROR {error}", file=sys.stderr)
        return 1

    try:
        if args.canonical:
            sys.stdout.buffer.write(canonical_bytes(manifest) + b"\n")
        elif args.digest:
            print(manifest_digest(manifest))
        else:
            suffix = f" (after {args.previous})" if args.previous else ""
            print(f"valid Campaign Manifest v0: {args.manifest}{suffix}")
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
