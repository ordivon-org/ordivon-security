from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation.windows_kvm_build import (
    WindowsKvmBaseBuildConfig,
    build_windows_kvm_base,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and seal one deny-all Windows 11 Enterprise Evaluation KVM base image."
    )
    parser.add_argument("--source-iso", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=6144)
    parser.add_argument("--vcpus", type=int, default=4)
    parser.add_argument("--disk-size-gib", type=int, default=80)
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    receipt = build_windows_kvm_base(
        WindowsKvmBaseBuildConfig(
            state_root=args.state_root,
            source_iso_path=args.source_iso,
            memory_mib=args.memory_mib,
            vcpu_count=args.vcpus,
            disk_size_gib=args.disk_size_gib,
            installation_timeout_seconds=args.timeout_seconds,
        )
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
