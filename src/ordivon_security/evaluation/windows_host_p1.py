from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_digest

from .windows_kvm import _digest_path, _replace_private_json

_RESOLVE_PATH = Path("/mnt/c/Program Files/厂商B Design/目标产品B Resolve/Resolve.exe")
_INTL_PATH = Path("/mnt/c/Program Files/厂商B Design/目标产品B Resolve/intl.dll")


def collect_windows_host_resolve_baseline(
    powershell_path: Path,
    script_path: Path,
    receipt_path: Path,
    timeout_seconds: int = 180,
) -> JsonObject:
    watched = (_RESOLVE_PATH, _INTL_PATH)
    before: dict[str, tuple[str, int]] = {}
    for path in watched:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Expected host baseline file is missing or unsafe: {path}")
        before[str(path)] = _digest_path(path)
    if powershell_path.is_symlink() or not powershell_path.is_file():
        raise ValueError("Windows PowerShell path is missing or unsafe")
    if script_path.is_symlink() or not script_path.is_file():
        raise ValueError("Host baseline script is missing or unsafe")
    completed = subprocess.run(
        [
            str(powershell_path),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script_path.read_text(encoding="utf-8"),
        ],
        check=False,
        capture_output=True,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Windows host baseline failed ({completed.returncode}): {completed.stderr[:4096]!r}"
        )
    value = json.loads(completed.stdout.decode("utf-8-sig").strip())
    if not isinstance(value, dict):
        raise ValueError("Windows host baseline did not return an object")
    if value.get("kind") != "ordivon.security.windows-host-caseb-free-baseline":
        raise ValueError("Windows host baseline kind is invalid")
    if value.get("readOnly") is not True or value.get("hostModified") is not False:
        raise ValueError("Windows host baseline did not preserve read-only semantics")
    after = {str(path): _digest_path(path) for path in watched}
    if after != before:
        raise RuntimeError("Windows host Resolve identity changed during baseline collection")
    powershell_digest, powershell_length = _digest_path(powershell_path)
    script_digest, script_length = _digest_path(script_path)
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.windows-host-caseb-free-baseline-receipt",
        "status": "captured-read-only",
        "capturedAtMs": time.time_ns() // 1_000_000,
        "collector": {
            "powershell": {
                "digest": powershell_digest,
                "byteLength": powershell_length,
            },
            "script": {"digest": script_digest, "byteLength": script_length},
        },
        "before": {
            path: {"digest": digest, "byteLength": length}
            for path, (digest, length) in before.items()
        },
        "after": {
            path: {"digest": digest, "byteLength": length}
            for path, (digest, length) in after.items()
        },
        "baseline": cast(JsonObject, value),
        "readOnly": True,
        "hostModified": False,
    }
    receipt["receiptDigest"] = canonical_digest(receipt)
    _replace_private_json(receipt_path, receipt)
    return receipt
