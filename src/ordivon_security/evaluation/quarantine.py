from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_bytes


def harden_quarantine_tree(root: Path, *, receipt_path: Path | None = None) -> JsonObject:
    """Apply owner-only, non-executable permissions to an existing quarantine tree."""

    if root.is_symlink() or not root.is_dir():
        raise ValueError("Quarantine root must be a regular non-symlink directory")
    if receipt_path is not None:
        if receipt_path.is_symlink():
            raise ValueError("Quarantine receipt path must not be a symlink")
        if receipt_path.exists():
            raise FileExistsError(f"Quarantine receipt already exists: {receipt_path}")

    directories: list[Path] = []
    files: list[Path] = []
    rejected: list[str] = []
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        metadata = current_path.stat(follow_symlinks=False)
        if current_path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            rejected.append(str(current_path))
            directory_names[:] = []
            continue
        directories.append(current_path)
        safe_directories: list[str] = []
        for name in directory_names:
            path = current_path / name
            child = path.stat(follow_symlinks=False)
            if path.is_symlink() or not stat.S_ISDIR(child.st_mode):
                rejected.append(str(path))
            else:
                safe_directories.append(name)
        directory_names[:] = safe_directories
        for name in file_names:
            path = current_path / name
            child = path.stat(follow_symlinks=False)
            if path.is_symlink() or not stat.S_ISREG(child.st_mode):
                rejected.append(str(path))
            else:
                files.append(path)
    if rejected:
        raise ValueError(
            "Quarantine tree contains symbolic links or special files: "
            + ", ".join(sorted(rejected)[:8])
        )

    changed_count = 0
    for path in directories:
        if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != 0o700:
            path.chmod(0o700, follow_symlinks=False)
            changed_count += 1
    for path in files:
        if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != 0o600:
            path.chmod(0o600, follow_symlinks=False)
            changed_count += 1

    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.quarantine-hardening-receipt",
        "root": str(root),
        "directories": len(directories),
        "files": len(files),
        "changedEntries": changed_count,
        "directoryMode": "0700",
        "fileMode": "0600",
        "sampleExecution": False,
        "completedAtMs": time.time_ns() // 1_000_000,
    }
    if receipt_path is not None:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.parent.chmod(0o700)
        with receipt_path.open("xb") as handle:
            handle.write(canonical_bytes(receipt) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        receipt_path.chmod(0o600)
    return receipt
