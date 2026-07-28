#!/usr/bin/env python3
"""Run the first live Security + Link + Edge + Runtime infrastructure Campaign."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ordivon_security_contracts.live_composition import (  # noqa: E402
    LiveCompositionConfig,
    run_live_composition,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-template", type=Path, required=True)
    parser.add_argument("--link-manifest-template", type=Path, required=True)
    parser.add_argument("--link-security-executable", type=Path, required=True)
    parser.add_argument("--link-world-executable", type=Path, required=True)
    parser.add_argument("--edge-cwd", type=Path, required=True)
    parser.add_argument("--edge-command", action="append", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--runtime-workspace-id", required=True)
    parser.add_argument("--runtime-source-revision", required=True)
    parser.add_argument("--runtime-client-request-id", required=True)
    parser.add_argument("--security-source-revision", required=True)
    arguments = parser.parse_args()

    config = LiveCompositionConfig(
        campaign_template=arguments.campaign_template,
        link_manifest_template=arguments.link_manifest_template,
        link_security_executable=arguments.link_security_executable,
        link_world_executable=arguments.link_world_executable,
        edge_command=tuple(arguments.edge_command),
        edge_cwd=arguments.edge_cwd,
        output_root=arguments.output_root,
        runtime_workspace_id=arguments.runtime_workspace_id,
        runtime_source_revision=arguments.runtime_source_revision,
        runtime_client_request_id=arguments.runtime_client_request_id,
        security_source_revision=arguments.security_source_revision,
    )
    try:
        result = run_live_composition(config)
    except Exception as error:  # top-level acceptance boundary
        print(f"{error.__class__.__name__}: {str(error)[:4096]}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
