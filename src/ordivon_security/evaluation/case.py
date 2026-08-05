from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from ordivon_security._canonical import (
    JsonObject,
    JsonValue,
    canonical_bytes,
    canonical_digest,
    validate_json,
)
from ordivon_security.identity import security_source_identity

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_CHUNK_BYTES = 4 * 1024 * 1024


class CaseExecutionStatus(StrEnum):
    STATIC_ONLY = "static-only"
    EXTERNAL_UNCONTROLLED_EXECUTION = "external-uncontrolled-execution"
    CONTROLLED_TRIAL = "controlled-trial"


@dataclass(frozen=True, slots=True)
class CaseSnapshotBundle:
    path: Path
    snapshot_id: str
    manifest_digest: str
    entry_count: int
    file_count: int
    total_file_bytes: int
    quarantine_compliant: bool

    def to_dict(self) -> JsonObject:
        return {
            "path": str(self.path),
            "snapshotId": self.snapshot_id,
            "manifestDigest": self.manifest_digest,
            "entryCount": self.entry_count,
            "fileCount": self.file_count,
            "totalFileBytes": self.total_file_bytes,
            "quarantineCompliant": self.quarantine_compliant,
        }


@dataclass(frozen=True, slots=True)
class _InventoryRecord:
    relative_path: str
    entry_type: str
    mode: int
    device: int
    inode: int
    byte_length: int
    modified_ns: int


def _validate_root(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Case root must be a regular non-symlink directory")
    return root.resolve()


def _relative(root: Path, path: Path) -> str:
    if path == root:
        return "."
    return path.relative_to(root).as_posix()


def _mode_string(mode: int) -> str:
    return f"{mode:04o}"


def _open_regular_nofollow(path: Path) -> BinaryIO:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Case entry is not a regular file: {path}")
        return os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise


def _write_private_json(path: Path, value: JsonObject) -> None:
    if path.is_symlink():
        raise ValueError("Receipt path must not be a symlink")
    if path.exists():
        raise FileExistsError(f"Receipt already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(_PRIVATE_DIRECTORY_MODE)
    with path.open("xb") as handle:
        handle.write(canonical_bytes(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(_PRIVATE_FILE_MODE)


def audit_quarantine_tree(root: Path) -> JsonObject:
    resolved = _validate_root(root)
    directory_count = 0
    file_count = 0
    total_file_bytes = 0
    non_private_directories: list[JsonValue] = []
    non_private_files: list[JsonValue] = []
    executable_files: list[JsonValue] = []
    symbolic_links: list[JsonValue] = []
    special_entries: list[JsonValue] = []

    for current, directory_names, file_names in os.walk(
        resolved,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        current_metadata = current_path.stat(follow_symlinks=False)
        current_mode = stat.S_IMODE(current_metadata.st_mode)
        directory_count += 1
        if current_mode != _PRIVATE_DIRECTORY_MODE:
            non_private_directories.append(
                {
                    "path": _relative(resolved, current_path),
                    "mode": _mode_string(current_mode),
                }
            )

        safe_directories: list[str] = []
        for name in directory_names:
            path = current_path / name
            metadata = path.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                symbolic_links.append({"path": _relative(resolved, path), "entryType": "link"})
            elif stat.S_ISDIR(metadata.st_mode):
                safe_directories.append(name)
            else:
                special_entries.append(
                    {
                        "path": _relative(resolved, path),
                        "mode": _mode_string(stat.S_IMODE(metadata.st_mode)),
                    }
                )
        directory_names[:] = safe_directories

        for name in file_names:
            path = current_path / name
            metadata = path.stat(follow_symlinks=False)
            relative_path = _relative(resolved, path)
            if stat.S_ISLNK(metadata.st_mode):
                symbolic_links.append({"path": relative_path, "entryType": "link"})
                continue
            if not stat.S_ISREG(metadata.st_mode):
                special_entries.append(
                    {
                        "path": relative_path,
                        "mode": _mode_string(stat.S_IMODE(metadata.st_mode)),
                    }
                )
                continue
            file_count += 1
            total_file_bytes += metadata.st_size
            mode = stat.S_IMODE(metadata.st_mode)
            if mode != _PRIVATE_FILE_MODE:
                non_private_files.append({"path": relative_path, "mode": _mode_string(mode)})
            if mode & 0o111:
                executable_files.append({"path": relative_path, "mode": _mode_string(mode)})

    compliant = not (
        non_private_directories
        or non_private_files
        or executable_files
        or symbolic_links
        or special_entries
    )
    audit: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.quarantine-audit",
        "security": security_source_identity(),
        "root": str(resolved),
        "auditedAtMs": time.time_ns() // 1_000_000,
        "directories": directory_count,
        "files": file_count,
        "totalFileBytes": total_file_bytes,
        "expectedDirectoryMode": "0700",
        "expectedFileMode": "0600",
        "nonPrivateDirectories": non_private_directories,
        "nonPrivateFiles": non_private_files,
        "executableFiles": executable_files,
        "symbolicLinks": symbolic_links,
        "specialEntries": special_entries,
        "compliant": compliant,
    }
    validate_json(audit)
    return audit


def write_quarantine_audit(root: Path, receipt_path: Path) -> JsonObject:
    audit = audit_quarantine_tree(root)
    _write_private_json(receipt_path, audit)
    return audit


def _capture_inventory(root: Path) -> tuple[_InventoryRecord, ...]:
    records: list[_InventoryRecord] = []
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        current_metadata = current_path.stat(follow_symlinks=False)
        if not stat.S_ISDIR(current_metadata.st_mode):
            raise ValueError(f"Case directory changed type during snapshot: {current_path}")
        records.append(
            _InventoryRecord(
                relative_path=_relative(root, current_path),
                entry_type="directory",
                mode=stat.S_IMODE(current_metadata.st_mode),
                device=current_metadata.st_dev,
                inode=current_metadata.st_ino,
                byte_length=0,
                modified_ns=current_metadata.st_mtime_ns,
            )
        )
        safe_directories: list[str] = []
        for name in directory_names:
            path = current_path / name
            metadata = path.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"Case snapshot rejects symbolic links: {path}")
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"Case snapshot rejects special entries: {path}")
            safe_directories.append(name)
        directory_names[:] = sorted(safe_directories)
        for name in sorted(file_names):
            path = current_path / name
            metadata = path.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"Case snapshot rejects symbolic links: {path}")
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"Case snapshot rejects special entries: {path}")
            records.append(
                _InventoryRecord(
                    relative_path=_relative(root, path),
                    entry_type="file",
                    mode=stat.S_IMODE(metadata.st_mode),
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    byte_length=metadata.st_size,
                    modified_ns=metadata.st_mtime_ns,
                )
            )
    return tuple(sorted(records, key=lambda record: (record.relative_path, record.entry_type)))


def _hash_inventory(root: Path, inventory: tuple[_InventoryRecord, ...]) -> list[JsonValue]:
    entries: list[JsonValue] = []
    for record in inventory:
        entry: JsonObject = {
            "path": record.relative_path,
            "entryType": record.entry_type,
            "mode": _mode_string(record.mode),
        }
        if record.entry_type == "file":
            path = root / record.relative_path
            digest = hashlib.sha256()
            with _open_regular_nofollow(path) as handle:
                before = os.fstat(handle.fileno())
                if (
                    before.st_dev != record.device
                    or before.st_ino != record.inode
                    or before.st_size != record.byte_length
                    or before.st_mtime_ns != record.modified_ns
                    or stat.S_IMODE(before.st_mode) != record.mode
                ):
                    raise ValueError(f"Case file changed before hashing: {record.relative_path}")
                while chunk := handle.read(_CHUNK_BYTES):
                    digest.update(chunk)
                after = os.fstat(handle.fileno())
                if (
                    after.st_dev != record.device
                    or after.st_ino != record.inode
                    or after.st_size != record.byte_length
                    or after.st_mtime_ns != record.modified_ns
                    or stat.S_IMODE(after.st_mode) != record.mode
                ):
                    raise ValueError(f"Case file changed while hashing: {record.relative_path}")
            entry["byteLength"] = record.byte_length
            entry["sha256"] = "sha256:" + digest.hexdigest()
        entries.append(entry)
    return entries


def _policy_summary(entries: list[JsonValue]) -> JsonObject:
    non_private_directories = 0
    non_private_files = 0
    executable_files = 0
    for value in entries:
        if not isinstance(value, dict):
            raise TypeError("Case snapshot entry must be an object")
        entry_type = value.get("entryType")
        mode_value = value.get("mode")
        if not isinstance(mode_value, str):
            raise TypeError("Case snapshot mode must be text")
        mode = int(mode_value, 8)
        if entry_type == "directory" and mode != _PRIVATE_DIRECTORY_MODE:
            non_private_directories += 1
        elif entry_type == "file":
            if mode != _PRIVATE_FILE_MODE:
                non_private_files += 1
            if mode & 0o111:
                executable_files += 1
    return {
        "expectedDirectoryMode": "0700",
        "expectedFileMode": "0600",
        "nonPrivateDirectoryCount": non_private_directories,
        "nonPrivateFileCount": non_private_files,
        "executableFileCount": executable_files,
        "compliant": not (non_private_directories or non_private_files or executable_files),
    }


def _validate_snapshot_inputs(
    *,
    case_id: str,
    execution_status: CaseExecutionStatus,
    source_evaluation_run_ids: tuple[str, ...],
    limitations: tuple[str, ...],
) -> None:
    if not case_id.startswith("case:") or case_id != case_id.strip():
        raise ValueError("Case identity must be trimmed and start with case:")
    if len(source_evaluation_run_ids) != len(set(source_evaluation_run_ids)):
        raise ValueError("Source Evaluation Run identities must be unique")
    for run_id in source_evaluation_run_ids:
        if not run_id.startswith("evaluation-run:") or run_id != run_id.strip():
            raise ValueError("Source Evaluation Run identity is invalid")
    if len(limitations) != len(set(limitations)):
        raise ValueError("Case snapshot limitations must be unique")
    for limitation in limitations:
        if not limitation or limitation != limitation.strip():
            raise ValueError("Case snapshot limitation must be non-empty and trimmed")
    if execution_status is CaseExecutionStatus.EXTERNAL_UNCONTROLLED_EXECUTION and not limitations:
        raise ValueError("External uncontrolled execution requires explicit limitations")
    if execution_status is CaseExecutionStatus.CONTROLLED_TRIAL and not source_evaluation_run_ids:
        raise ValueError("Controlled Trial status requires a source Evaluation Run")


def create_case_snapshot(
    root: Path,
    output_path: Path,
    *,
    case_id: str,
    execution_status: CaseExecutionStatus,
    source_evaluation_run_ids: tuple[str, ...] = (),
    limitations: tuple[str, ...] = (),
) -> CaseSnapshotBundle:
    _validate_snapshot_inputs(
        case_id=case_id,
        execution_status=execution_status,
        source_evaluation_run_ids=source_evaluation_run_ids,
        limitations=limitations,
    )
    resolved = _validate_root(root)
    resolved_output = output_path.resolve(strict=False)
    if resolved_output == resolved or resolved in resolved_output.parents:
        raise ValueError("Case snapshot output must be outside the Case root")
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError(f"Case snapshot output already exists: {output_path}")

    initial_inventory = _capture_inventory(resolved)
    entries = _hash_inventory(resolved, initial_inventory)
    final_inventory = _capture_inventory(resolved)
    if initial_inventory != final_inventory:
        raise ValueError("Case tree changed while the snapshot was being created")

    file_records = tuple(record for record in initial_inventory if record.entry_type == "file")
    directory_records = tuple(
        record for record in initial_inventory if record.entry_type == "directory"
    )
    policy = _policy_summary(entries)
    manifest: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.case-snapshot",
        "caseId": case_id,
        "executionStatus": execution_status.value,
        "sourceEvaluationRunIds": list(source_evaluation_run_ids),
        "limitations": list(limitations),
        "security": security_source_identity(),
        "directoryCount": len(directory_records),
        "fileCount": len(file_records),
        "entryCount": len(initial_inventory),
        "totalFileBytes": sum(record.byte_length for record in file_records),
        "quarantinePolicy": policy,
        "entries": entries,
    }
    validate_json(manifest)
    manifest_digest = canonical_digest(manifest)
    snapshot_id = f"case-snapshot:{manifest_digest.removeprefix('sha256:')[:24]}"
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.case-snapshot-receipt",
        "snapshotId": snapshot_id,
        "caseId": case_id,
        "root": str(resolved),
        "recordedAtMs": time.time_ns() // 1_000_000,
        "manifestDigest": manifest_digest,
        "entryCount": len(initial_inventory),
        "fileCount": len(file_records),
        "totalFileBytes": sum(record.byte_length for record in file_records),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(_PRIVATE_DIRECTORY_MODE)
    staging_path = Path(tempfile.mkdtemp(prefix=".case-snapshot-", dir=output_path.parent))
    staging_path.chmod(_PRIVATE_DIRECTORY_MODE)
    try:
        _write_private_json(staging_path / "case-manifest.json", manifest)
        _write_private_json(staging_path / "snapshot-receipt.json", receipt)
        directory_descriptor = os.open(staging_path, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        os.rename(staging_path, output_path)
    finally:
        if staging_path.exists():
            shutil.rmtree(staging_path, ignore_errors=True)

    return CaseSnapshotBundle(
        path=output_path,
        snapshot_id=snapshot_id,
        manifest_digest=manifest_digest,
        entry_count=len(initial_inventory),
        file_count=len(file_records),
        total_file_bytes=sum(record.byte_length for record in file_records),
        quarantine_compliant=bool(policy["compliant"]),
    )


def _load_object(path: Path, label: str) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    validate_json(value)
    return value


def verify_case_snapshot(path: Path) -> str:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("Case snapshot path must be a regular directory")
    if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != _PRIVATE_DIRECTORY_MODE:
        raise ValueError("Case snapshot directory is not private")
    expected_members = {"case-manifest.json", "snapshot-receipt.json"}
    actual_members = {candidate.name for candidate in path.iterdir()}
    if actual_members != expected_members:
        raise ValueError("Case snapshot contains unexpected or missing files")
    manifest_path = path / "case-manifest.json"
    receipt_path = path / "snapshot-receipt.json"
    for candidate in (manifest_path, receipt_path):
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("Case snapshot file is missing or unsafe")
        if stat.S_IMODE(candidate.stat(follow_symlinks=False).st_mode) != _PRIVATE_FILE_MODE:
            raise ValueError("Case snapshot file is not private")
    manifest = _load_object(manifest_path, "Case snapshot manifest")
    receipt = _load_object(receipt_path, "Case snapshot receipt")
    if (
        manifest.get("schemaVersion") != 1
        or manifest.get("kind") != "ordivon.security.case-snapshot"
    ):
        raise ValueError("Case snapshot manifest schema is unsupported")
    if (
        receipt.get("schemaVersion") != 1
        or receipt.get("kind") != "ordivon.security.case-snapshot-receipt"
    ):
        raise ValueError("Case snapshot receipt schema is unsupported")
    manifest_digest = canonical_digest(manifest)
    if receipt.get("manifestDigest") != manifest_digest:
        raise ValueError("Case snapshot manifest digest differs from its receipt")
    case_id = manifest.get("caseId")
    execution_status_value = manifest.get("executionStatus")
    source_run_values = manifest.get("sourceEvaluationRunIds")
    limitation_values = manifest.get("limitations")
    if (
        not isinstance(case_id, str)
        or not isinstance(execution_status_value, str)
        or not isinstance(source_run_values, list)
        or not all(isinstance(value, str) for value in source_run_values)
        or not isinstance(limitation_values, list)
        or not all(isinstance(value, str) for value in limitation_values)
    ):
        raise ValueError("Case snapshot identity or execution status is invalid")
    source_run_ids = tuple(value for value in source_run_values if isinstance(value, str))
    limitations = tuple(value for value in limitation_values if isinstance(value, str))
    if len(source_run_ids) != len(source_run_values) or len(limitations) != len(limitation_values):
        raise ValueError("Case snapshot Run identities or limitations are invalid")
    try:
        execution_status = CaseExecutionStatus(execution_status_value)
    except ValueError as error:
        raise ValueError("Case snapshot execution status is unsupported") from error
    _validate_snapshot_inputs(
        case_id=case_id,
        execution_status=execution_status,
        source_evaluation_run_ids=source_run_ids,
        limitations=limitations,
    )
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ValueError("Case snapshot entries must be a list")
    paths: list[str] = []
    directory_count = 0
    file_count = 0
    total_file_bytes = 0
    for value in entries:
        if not isinstance(value, dict):
            raise ValueError("Case snapshot entry must be an object")
        relative_path = value.get("path")
        entry_type = value.get("entryType")
        mode = value.get("mode")
        if not isinstance(relative_path, str) or not isinstance(mode, str):
            raise ValueError("Case snapshot entry path or mode is invalid")
        if entry_type not in {"directory", "file"}:
            raise ValueError("Case snapshot entry type is invalid")
        try:
            parsed_mode = int(mode, 8)
        except ValueError as error:
            raise ValueError("Case snapshot entry mode is invalid") from error
        if _mode_string(parsed_mode) != mode:
            raise ValueError("Case snapshot entry mode is not canonical")
        paths.append(relative_path)
        if entry_type == "directory":
            directory_count += 1
        else:
            digest = value.get("sha256")
            byte_length = value.get("byteLength")
            if (
                not isinstance(digest, str)
                or len(digest) != 71
                or not digest.startswith("sha256:")
                or digest.lower() != digest
                or not isinstance(byte_length, int)
                or isinstance(byte_length, bool)
                or byte_length < 0
            ):
                raise ValueError("Case snapshot file identity is invalid")
            try:
                bytes.fromhex(digest.removeprefix("sha256:"))
            except ValueError as error:
                raise ValueError("Case snapshot file digest is invalid") from error
            file_count += 1
            total_file_bytes += byte_length
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("Case snapshot entry paths are not ordered and unique")
    if manifest.get("entryCount") != len(entries) or receipt.get("entryCount") != len(entries):
        raise ValueError("Case snapshot entry count differs")
    if manifest.get("directoryCount") != directory_count:
        raise ValueError("Case snapshot directory count differs")
    if manifest.get("fileCount") != file_count or receipt.get("fileCount") != file_count:
        raise ValueError("Case snapshot file count differs")
    if manifest.get("quarantinePolicy") != _policy_summary(entries):
        raise ValueError("Case snapshot quarantine policy summary differs")
    if (
        manifest.get("totalFileBytes") != total_file_bytes
        or receipt.get("totalFileBytes") != total_file_bytes
    ):
        raise ValueError("Case snapshot total byte count differs")
    if receipt.get("caseId") != case_id:
        raise ValueError("Case snapshot Case identity differs")
    expected_snapshot_id = f"case-snapshot:{manifest_digest.removeprefix('sha256:')[:24]}"
    if receipt.get("snapshotId") != expected_snapshot_id:
        raise ValueError("Case snapshot identity differs")
    return manifest_digest


def verify_case_snapshot_against_root(path: Path, root: Path) -> str:
    manifest_digest = verify_case_snapshot(path)
    manifest = _load_object(path / "case-manifest.json", "Case snapshot manifest")
    resolved = _validate_root(root)
    initial_inventory = _capture_inventory(resolved)
    current_entries = _hash_inventory(resolved, initial_inventory)
    final_inventory = _capture_inventory(resolved)
    if initial_inventory != final_inventory:
        raise ValueError("Case tree changed while verifying the snapshot")
    if manifest.get("entries") != current_entries:
        raise ValueError("Case root differs from the retained snapshot")
    return manifest_digest
