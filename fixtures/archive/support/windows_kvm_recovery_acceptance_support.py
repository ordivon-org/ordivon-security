from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, validate_json
from ordivon_security.providers.windows_kvm import WindowsKvmMachineConfig
from ordivon_security.range.windows_fabric_reconcile import _identity_alive


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def ledger_semantic_binding(ledger: JsonObject) -> JsonObject | None:
    raw = ledger.get("actorReplacementRequest")
    if not isinstance(raw, dict):
        return None
    return cast(JsonObject, raw)


def host_namespace_truth(
    ledger: JsonObject,
    *,
    ip_path: Path = Path("/usr/bin/ip"),
) -> JsonObject:
    completed = subprocess.run(
        [str(ip_path), "netns", "list"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    names = sorted(line.split()[0] for line in completed.stdout.splitlines() if line.strip())
    candidates = ledger.get("ownedNamespaceCandidates")
    if not isinstance(candidates, list) or not all(isinstance(item, str) for item in candidates):
        raise ValueError("Range ledger lacks deterministic namespace candidates")
    owned = [name for name in cast(list[str], candidates) if name in names]
    fabric = ledger.get("fabricNamespace")
    bridge = ledger.get("bridgeName")
    ports: list[str] = []
    if isinstance(fabric, str) and fabric in names and isinstance(bridge, str):
        result = subprocess.run(
            [
                str(ip_path),
                "netns",
                "exec",
                fabric,
                "/usr/bin/bridge",
                "-j",
                "link",
                "show",
                "master",
                bridge,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout or "[]")
            ports = sorted(
                str(item.get("ifname"))
                for item in data
                if isinstance(item, dict) and item.get("ifname") is not None
            )
    truth: JsonObject = {
        "authority": "host-linux-netns-bridge-observation",
        "ownedNamespacesPresent": owned,
        "bridgePorts": ports,
        "fabricNamespacePresent": isinstance(fabric, str) and fabric in names,
    }
    validate_json(truth)
    return truth


def windows_kvm_machine_config(args: argparse.Namespace) -> WindowsKvmMachineConfig:
    return WindowsKvmMachineConfig(
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


def process_truth(ledger: JsonObject) -> JsonObject:
    truth: JsonObject = {
        "ownerAlive": _identity_alive(ledger.get("ownerPid"), ledger.get("ownerStartTime")),
        "qemuAlive": _identity_alive(ledger.get("qemuPid"), ledger.get("qemuStartTime")),
        "swtpmAlive": _identity_alive(ledger.get("swtpmPid"), ledger.get("swtpmStartTime")),
        "captureAlive": _identity_alive(ledger.get("capturePid"), ledger.get("captureStartTime")),
        "peerAlive": _identity_alive(ledger.get("peerPid"), ledger.get("peerStartTime")),
    }
    validate_json(truth)
    return truth
