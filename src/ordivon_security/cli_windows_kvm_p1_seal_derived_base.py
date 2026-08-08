from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation import SampleVault
from ordivon_security.evaluation.models import SampleIdentity
from ordivon_security.evaluation.windows_kvm_p1_derived_base import (
    WindowsKvmP1DerivedBaseConfig,
    WindowsKvmP1SealedResource,
    seal_windows_kvm_p1_derived_base,
)

_GENERIC_CONTROLLER = SampleIdentity.create(
    sha256="sha256:eb7e9874f1dc568721c826ea30e1b77f325254244564ca70381d2556f3d4388a",
    byte_length=25_600,
    media_type="application/vnd.microsoft.portable-executable",
    original_name="p1-controller.exe",
)
_EXECUTION_CONTROL_CANARY = SampleIdentity.create(
    sha256="sha256:d29becd1409bab42bbba885b3e6db5623cedaf61d83d6c3b01ed7111e347d655",
    byte_length=27_648,
    media_type="application/vnd.microsoft.portable-executable",
    original_name="p1-execution-control-canary.exe",
)
_ORCHESTRATOR = SampleIdentity.create(
    sha256="sha256:9f901eddccc3c0b510a39888d15d900748dccfe0c4516e94efad2798df3244e4",
    byte_length=13_224,
    media_type="text/x-powershell",
    original_name="p1-orchestrator.ps1",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Seal one layered P1 Windows base from the accepted parent and exact accepted "
            "generic-Controller/execution-control/orchestrator Vault objects. This command "
            "does not authorize or execute Case A."
        )
    )
    parser.add_argument("--parent-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--vault", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    vault = SampleVault(args.vault, max_sample_bytes=16 * 1024 * 1024)
    resources = (
        WindowsKvmP1SealedResource("generic-controller", _GENERIC_CONTROLLER),
        WindowsKvmP1SealedResource("execution-control-canary", _EXECUTION_CONTROL_CANARY),
        WindowsKvmP1SealedResource("orchestrator", _ORCHESTRATOR),
    )
    receipt = seal_windows_kvm_p1_derived_base(
        parent_manifest_path=args.parent_manifest,
        resources=resources,
        vault=vault,
        config=WindowsKvmP1DerivedBaseConfig(state_root=args.state_root),
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
