from __future__ import annotations

import shutil
import time
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue
from ordivon_security.providers.windows_kvm import (
    _fsync_directory,
    _load_object,
    _replace_private_json,
    _terminate_pid,
    process_identity_alive,
)


def _validated_run_path(runs_root: Path, ledger_path: Path, ledger: JsonObject) -> Path | None:
    value = ledger.get("runPath")
    if not isinstance(value, str):
        return None
    run_path = Path(value)
    if (
        not run_path.is_absolute()
        or run_path.parent != runs_root
        or ledger_path.stem != run_path.name
        or ledger.get("runId") != f"evaluation-run:{run_path.name}"
        or ledger.get("instanceId") != f"evaluation-instance:{run_path.name}"
    ):
        return None
    for key in (
        "overlayPath",
        "varsPath",
        "runDiskPath",
        "qmpPath",
        "tpmSocketPath",
        "tpmStatePath",
    ):
        item = ledger.get(key)
        if not isinstance(item, str):
            return None
        path = Path(item)
        if not path.is_absolute() or not path.is_relative_to(run_path):
            return None
    return run_path


def _active_benign_run_indices(proc_root: Path = Path("/proc")) -> set[int]:
    active: set[int] = set()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw_arguments = entry.joinpath("cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            continue
        arguments = [item.decode("utf-8", errors="replace") for item in raw_arguments if item]
        if "ordivon_security.cli_windows_kvm_acceptance" not in arguments:
            continue
        for index, value in enumerate(arguments[:-1]):
            if value != "--run-index":
                continue
            with suppress(ValueError):
                active.add(int(arguments[index + 1]))
    return active


def _reconcile_benign_fixtures(
    fixture_root: Path,
    *,
    active_indices: Iterable[int],
    diagnostics: Path,
) -> tuple[list[JsonObject], int, int]:
    active = set(active_indices)
    results: list[JsonObject] = []
    removed = 0
    skipped = 0
    if not fixture_root.exists():
        return results, removed, skipped
    for path in sorted(fixture_root.glob("ordivon-benign-v1-run-*.exe")):
        suffix = path.name.removeprefix("ordivon-benign-v1-run-").removesuffix(".exe")
        try:
            run_index = int(suffix)
        except ValueError:
            diagnostic = _write_diagnostic(
                diagnostics,
                "fixture",
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-kvm-reconciliation-diagnostic",
                    "decision": "attention-required",
                    "reason": "invalid-benign-fixture-name",
                    "path": str(path),
                },
            )
            results.append(
                {
                    "fixture": path.name,
                    "decision": "attention-required",
                    "reason": "invalid-benign-fixture-name",
                    "diagnosticPath": str(diagnostic),
                }
            )
            continue
        if path.is_symlink() or not path.is_file():
            diagnostic = _write_diagnostic(
                diagnostics,
                f"fixture-run-{run_index}",
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-kvm-reconciliation-diagnostic",
                    "decision": "attention-required",
                    "reason": "unsafe-benign-fixture-path",
                    "path": str(path),
                },
            )
            results.append(
                {
                    "fixtureRunIndex": run_index,
                    "decision": "attention-required",
                    "reason": "unsafe-benign-fixture-path",
                    "diagnosticPath": str(diagnostic),
                }
            )
            continue
        if run_index in active:
            skipped += 1
            results.append({"fixtureRunIndex": run_index, "decision": "skipped-active-fixture"})
            continue
        path.unlink()
        removed += 1
        results.append(
            {
                "fixtureRunIndex": run_index,
                "decision": "fixture-reconciled",
                "fixtureRemoved": True,
            }
        )
    if fixture_root.exists() and not any(fixture_root.iterdir()):
        fixture_root.rmdir()
    return results, removed, skipped


def _write_diagnostic(diagnostics: Path, token: str, payload: JsonObject) -> Path:
    path = diagnostics / f"{token}-{time.time_ns()}.json"
    _replace_private_json(path, payload)
    return path


def reconcile_windows_kvm_runs(
    state_root: Path,
    *,
    receipt_path: Path | None = None,
    diagnostics_root: Path | None = None,
) -> JsonObject:
    runs_root = state_root / "runs"
    ledgers_root = state_root / "run-ledgers"
    receipts_root = state_root / "receipts"
    diagnostics = diagnostics_root or state_root / "diagnostics" / "orphan-runs"
    for path, mode in (
        (runs_root, 0o710),
        (ledgers_root, 0o700),
        (receipts_root, 0o700),
        (diagnostics, 0o700),
    ):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
    results: list[JsonObject] = []
    managed_tokens: set[str] = set()
    for ledger_path in sorted(ledgers_root.glob("*.json")):
        token = ledger_path.stem
        try:
            ledger = _load_object(ledger_path, "Windows KVM Run state")
        except (ValueError, OSError) as error:
            diagnostic = _write_diagnostic(
                diagnostics,
                token,
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-kvm-reconciliation-diagnostic",
                    "decision": "attention-required",
                    "reason": "invalid-ledger",
                    "ledgerPath": str(ledger_path),
                    "errorType": type(error).__name__,
                },
            )
            results.append(
                {
                    "runToken": token,
                    "decision": "attention-required",
                    "reason": "invalid-ledger",
                    "diagnosticPath": str(diagnostic),
                }
            )
            continue
        if (
            ledger_path.is_symlink()
            or ledger.get("schemaVersion") != 1
            or ledger.get("kind") != "ordivon.security.windows-kvm-run-state"
            or ledger.get("providerId") != "provider:windows-kvm"
        ):
            run_path = None
        else:
            run_path = _validated_run_path(runs_root, ledger_path, ledger)
        if run_path is None:
            diagnostic = _write_diagnostic(
                diagnostics,
                token,
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-kvm-reconciliation-diagnostic",
                    "decision": "attention-required",
                    "reason": "unsafe-ledger",
                    "ledgerPath": str(ledger_path),
                },
            )
            results.append(
                {
                    "runToken": token,
                    "decision": "attention-required",
                    "reason": "unsafe-ledger",
                    "diagnosticPath": str(diagnostic),
                }
            )
            continue
        managed_tokens.add(token)
        if process_identity_alive(ledger.get("ownerPid"), ledger.get("ownerStartTime")):
            results.append(
                {"runToken": token, "decision": "skipped-active", "phase": ledger.get("phase")}
            )
            continue
        qemu_pid = ledger.get("qemuPid", 0)
        swtpm_pid = ledger.get("swtpmPid", 0)
        qemu_start = ledger.get("qemuStartTime")
        swtpm_start = ledger.get("swtpmStartTime")
        qemu_closed = (
            not isinstance(qemu_pid, int)
            or qemu_pid == 0
            or _terminate_pid(
                qemu_pid,
                expected_fragment="qemu-system-x86_64",
                expected_start_time=qemu_start if isinstance(qemu_start, int) else None,
            )
        )
        swtpm_closed = (
            not isinstance(swtpm_pid, int)
            or swtpm_pid == 0
            or _terminate_pid(
                swtpm_pid,
                expected_fragment="swtpm",
                expected_start_time=swtpm_start if isinstance(swtpm_start, int) else None,
            )
        )
        if qemu_closed and swtpm_closed:
            if run_path.exists():
                shutil.rmtree(run_path)
            ledger_path.unlink()
            _fsync_directory(ledgers_root)
            results.append(
                {
                    "runToken": token,
                    "decision": "reconciled",
                    "phase": ledger.get("phase"),
                    "qemuClosed": True,
                    "swtpmClosed": True,
                    "runDirectoryRemoved": not run_path.exists(),
                    "ledgerRemoved": not ledger_path.exists(),
                }
            )
        else:
            diagnostic = _write_diagnostic(
                diagnostics,
                token,
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-kvm-reconciliation-diagnostic",
                    "decision": "attention-required",
                    "reason": "process-identity-unresolved",
                    "ledgerPath": str(ledger_path),
                    "runPath": str(run_path),
                    "qemuClosed": qemu_closed,
                    "swtpmClosed": swtpm_closed,
                },
            )
            results.append(
                {
                    "runToken": token,
                    "decision": "attention-required",
                    "reason": "process-identity-unresolved",
                    "qemuClosed": qemu_closed,
                    "swtpmClosed": swtpm_closed,
                    "diagnosticPath": str(diagnostic),
                }
            )
    for run_path in sorted(path for path in runs_root.iterdir() if path.is_dir()):
        if run_path.name in managed_tokens:
            continue
        diagnostic = _write_diagnostic(
            diagnostics,
            run_path.name,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.windows-kvm-reconciliation-diagnostic",
                "decision": "attention-required",
                "reason": "run-directory-without-ledger",
                "runPath": str(run_path),
            },
        )
        results.append(
            {
                "runToken": run_path.name,
                "decision": "attention-required",
                "reason": "run-directory-without-ledger",
                "diagnosticPath": str(diagnostic),
            }
        )
    fixture_results, fixtures_removed, fixtures_skipped = _reconcile_benign_fixtures(
        state_root / "fixtures",
        active_indices=_active_benign_run_indices(),
        diagnostics=diagnostics,
    )
    results.extend(fixture_results)
    attention = sum(item.get("decision") == "attention-required" for item in results)
    payload: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.windows-kvm-reconciliation-receipt",
        "recordedAtNs": time.time_ns(),
        "stateRoot": str(state_root),
        "results": cast(list[JsonValue], results),
        "reconciled": sum(item.get("decision") == "reconciled" for item in results),
        "skippedActive": sum(item.get("decision") == "skipped-active" for item in results),
        "attentionRequired": attention,
        "fixtureFilesRemoved": fixtures_removed,
        "fixtureFilesSkippedActive": fixtures_skipped,
        "status": "passed" if attention == 0 else "attention-required",
    }
    if receipt_path is None:
        receipt_path = receipts_root / f"windows-kvm-reconcile-{time.time_ns()}.json"
    _replace_private_json(receipt_path, payload)
    return payload
