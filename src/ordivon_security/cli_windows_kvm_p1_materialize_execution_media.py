from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security.evaluation.windows_kvm_p1_cases import (
    CapabilityCase,
    EnvironmentTransformationManifest,
)
from ordivon_security.evaluation.windows_kvm_p1_execution_media import (
    WindowsKvmP1ExecutionContract,
    WindowsKvmP1ExecutionMediaConfig,
    materialize_windows_kvm_p1_execution_media,
)
from ordivon_security.providers.windows_kvm import load_json_object as _load_object


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Materialize a complete, digest-bound, QEMU-read-only NTFS execution-tree "
            "candidate for Case A. This command does not attach a VM or execute code."
        )
    )
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--case-manifest", type=Path, required=True)
    parser.add_argument("--transform-manifest", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    contract = WindowsKvmP1ExecutionContract.from_dict(
        _load_object(args.contract, "Windows KVM P1 execution contract")
    )
    case_value = _load_object(args.case_manifest, "Windows KVM P1 Capability Case")
    case = CapabilityCase.from_dict(case_value)
    transformation = EnvironmentTransformationManifest.from_dict(
        _load_object(args.transform_manifest, "Windows KVM P1 transformation manifest")
    )
    result = materialize_windows_kvm_p1_execution_media(
        contract,
        case_value,
        case,
        transformation,
        args.source,
        WindowsKvmP1ExecutionMediaConfig(state_root=args.state_root),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
