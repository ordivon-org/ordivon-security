from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation.windows_kvm_p1 import (
    WindowsKvmInstallerProfile,
    WindowsKvmP1MediaConfig,
    prepare_windows_kvm_installer_media,
)
from ordivon_security.providers.windows_kvm import load_json_object as _load_object


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a digest-bound, NTFS, QEMU-read-only input disk for an authorized "
            "Windows installer Case. This command does not execute the installer."
        )
    )
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    profile = WindowsKvmInstallerProfile.from_dict(
        _load_object(args.profile, "Windows KVM P1 installer profile")
    )
    result = prepare_windows_kvm_installer_media(
        profile,
        args.source,
        WindowsKvmP1MediaConfig(state_root=args.state_root),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
