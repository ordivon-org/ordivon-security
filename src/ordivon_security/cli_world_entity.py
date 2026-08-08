from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject
from ordivon_security.world_boundary import (
    WorldEntityKvmConfig,
    WorldEntityKvmDestination,
    WorldEntityMigrationRequestError,
    rejected_world_entity_response,
)
from ordivon_security.providers.windows_kvm import WindowsKvmMachineConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Materialize or reconcile one source-departed Entity as a Windows KVM "
            "continuity carrier."
        )
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--destination-world-id", required=True)
    parser.add_argument("--allow-source-world", action="append", default=[])
    parser.add_argument("--memory-mib", type=int, default=1024)
    parser.add_argument("--vcpus", type=int, default=1)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    machine = WindowsKvmMachineConfig(
        state_root=args.state_root,
        base_manifest_path=args.base_manifest,
        qemu_path=Path("/usr/bin/qemu-system-x86_64"),
        qemu_img_path=Path("/usr/bin/qemu-img"),
        swtpm_path=Path("/usr/bin/swtpm"),
        setpriv_path=Path("/usr/bin/setpriv"),
        firmware_code_path=Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
        run_user="qemu",
        run_group="qemu",
        memory_mib=args.memory_mib,
        vcpu_count=args.vcpus,
        qmp_ready_timeout_seconds=60,
        shutdown_grace_seconds=15,
    )
    destination = WorldEntityKvmDestination(
        WorldEntityKvmConfig(
            machine=machine,
            destination_world_id=args.destination_world_id,
            allowed_source_world_ids=tuple(args.allow_source_world),
        )
    )
    raw = json.load(sys.stdin)
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise SystemExit("Entity Migration request must be a JSON object")
    try:
        response = destination.handle(cast(JsonObject, raw))
    except WorldEntityMigrationRequestError as error:
        response = rejected_world_entity_response(error)
    print(json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
