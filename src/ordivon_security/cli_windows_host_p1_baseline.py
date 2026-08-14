from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation.windows_host_p1 import (
    collect_windows_host_caseb_baseline,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture the existing Windows 目标产品B  Free control read-only."
    )
    parser.add_argument(
        "--powershell",
        type=Path,
        default=Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
    )
    parser.add_argument(
        "--script",
        type=Path,
        default=(
            Path(__file__).parent
            / "resources"
            / "windows_kvm"
            / "windows-host-caseb-baseline.ps1"
        ),
    )
    parser.add_argument("--receipt", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = collect_windows_host_caseb_baseline(
        args.powershell,
        args.script,
        args.receipt,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
