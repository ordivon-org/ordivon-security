from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue
from ordivon_security.providers.windows_kvm import (
    _fsync_directory,
    _load_object,
    _process_identity,
    _replace_private_json,
    _terminate_pid,
)

_SUPPORTED_RANGES = {
    "range:windows-isolated-fabric-s5": "s5",
    "range:windows-topology-churn-s6": "s6",
}


def _identity_alive(pid: object, start_time: object) -> bool:
    if not isinstance(pid, int) or pid < 1 or not isinstance(start_time, int):
        return False
    identity = _process_identity(pid)
    return identity is not None and identity[1] == start_time and identity[0] != "Z"


def _session_token(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]


def _expected_namespaces(prefix: str, token: str) -> tuple[str, ...]:
    if prefix == "s5":
        return (f"s5f{token}", f"s5p{token}")
    return (f"s6f{token}", f"s6p{token}", f"s6q{token}")


def _expected_host_links(prefix: str, token: str) -> tuple[str, ...]:
    if prefix == "s5":
        return ()
    return (f"q{token}", f"w{token}")


def _validated_range_ledger(
    state_root: Path,
    runs_root: Path,
    ledger_path: Path,
    ledger: JsonObject,
) -> tuple[Path, tuple[str, ...], tuple[str, ...], Path | None] | None:
    if (
        ledger_path.is_symlink()
        or ledger.get("schemaVersion") != 1
        or ledger.get("kind") != "ordivon.security.windows-kvm-run-state"
        or ledger.get("providerId") != "provider:windows-kvm"
        or ledger.get("networkMode") != "isolated-l2-no-uplink"
    ):
        return None
    range_id = ledger.get("rangeId")
    prefix = _SUPPORTED_RANGES.get(range_id) if isinstance(range_id, str) else None
    session_id = ledger.get("rangeSessionId")
    if (
        prefix is None
        or not isinstance(session_id, str)
        or not session_id.startswith("range-session:")
    ):
        return None
    token = _session_token(session_id)
    run_token = f"{prefix}-{token}"
    run_path = Path(str(ledger.get("runPath", "")))
    if (
        not run_path.is_absolute()
        or run_path.parent != runs_root
        or run_path.name != run_token
        or ledger_path.parent != state_root / "run-ledgers"
        or ledger_path.name != f"{run_token}.json"
        or ledger.get("instanceId") != f"range-instance:{run_token}"
    ):
        return None
    for key in (
        "overlayPath",
        "varsPath",
        "qmpPath",
        "tpmSocketPath",
        "tpmStatePath",
    ):
        value = ledger.get(key)
        if not isinstance(value, str):
            return None
        path = Path(value)
        if not path.is_absolute() or not path.is_relative_to(run_path):
            return None

    expected_namespaces = _expected_namespaces(prefix, token)
    candidates = ledger.get("ownedNamespaceCandidates")
    if not isinstance(candidates, list) or tuple(candidates) != expected_namespaces:
        return None
    fabric_namespace = ledger.get("fabricNamespace")
    if fabric_namespace != expected_namespaces[0]:
        return None
    peer_namespace = ledger.get("peerNamespace")
    if peer_namespace is not None and peer_namespace not in expected_namespaces[1:]:
        return None

    expected_host_links = _expected_host_links(prefix, token)
    host_link_candidates = ledger.get("ownedHostLinkCandidates", [])
    if (
        not isinstance(host_link_candidates, list)
        or tuple(host_link_candidates) != expected_host_links
    ):
        return None

    canary_path: Path | None = None
    raw_canary = ledger.get("canaryPath")
    if raw_canary is not None:
        if not isinstance(raw_canary, str):
            return None
        candidate = Path(raw_canary)
        canaries_root = state_root / "canaries"
        if not candidate.is_absolute() or candidate.parent != canaries_root:
            return None
        canary_path = candidate
    return run_path, expected_namespaces, expected_host_links, canary_path


def _terminate_from_ledger(
    ledger: JsonObject,
    *,
    pid_key: str,
    start_key: str,
    expected_fragment: str,
) -> bool:
    pid = ledger.get(pid_key, 0)
    start = ledger.get(start_key)
    if not isinstance(pid, int) or pid == 0:
        return True
    return _terminate_pid(
        pid,
        expected_fragment=expected_fragment,
        expected_start_time=start if isinstance(start, int) else None,
    )


def _listed_namespaces(ip_path: Path) -> set[str]:
    completed = subprocess.run(
        [str(ip_path), "netns", "list"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=15,
    )
    return {line.split()[0] for line in completed.stdout.splitlines() if line.strip()}


def _remove_namespaces(ip_path: Path, names: tuple[str, ...]) -> tuple[list[str], list[str]]:
    present = _listed_namespaces(ip_path)
    requested = [name for name in names if name in present]
    for name in requested:
        subprocess.run(
            [str(ip_path), "netns", "del", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=15,
        )
    remaining = _listed_namespaces(ip_path)
    residual = [name for name in names if name in remaining]
    return requested, residual


def _root_link_kinds(ip_path: Path, names: tuple[str, ...]) -> dict[str, str | None]:
    completed = subprocess.run(
        [str(ip_path), "-d", "-j", "link", "show"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=15,
    )
    if completed.returncode != 0:
        return {name: None for name in names}
    try:
        data = json.loads(completed.stdout or "[]")
    except ValueError:
        return {name: None for name in names}
    observed: dict[str, str | None] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get("ifname")
        if name not in names:
            continue
        linkinfo = item.get("linkinfo")
        kind = linkinfo.get("info_kind") if isinstance(linkinfo, dict) else None
        observed[cast(str, name)] = kind if isinstance(kind, str) else None
    return observed


def _remove_host_links(ip_path: Path, names: tuple[str, ...]) -> tuple[list[str], list[str]]:
    before = _root_link_kinds(ip_path, names)
    unsafe = [name for name, kind in before.items() if kind != "veth"]
    if unsafe:
        return [], sorted(before)
    requested = sorted(before)
    for name in names:
        current = _root_link_kinds(ip_path, names)
        if name not in current:
            continue
        subprocess.run(
            [str(ip_path), "link", "del", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=15,
        )
    residual = sorted(_root_link_kinds(ip_path, names))
    return requested, residual


def _write_diagnostic(diagnostics: Path, token: str, payload: JsonObject) -> Path:
    path = diagnostics / f"{token}-{time.time_ns()}.json"
    _replace_private_json(path, payload)
    return path


def reconcile_windows_fabric_range_runs(
    state_root: Path,
    *,
    receipt_path: Path | None = None,
    diagnostics_root: Path | None = None,
    ip_path: Path = Path("/usr/bin/ip"),
) -> JsonObject:
    runs_root = state_root / "runs"
    ledgers_root = state_root / "run-ledgers"
    receipts_root = state_root / "receipts"
    diagnostics = diagnostics_root or state_root / "diagnostics" / "orphan-ranges"
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
            ledger = _load_object(ledger_path, "Windows fabric Range Run state")
        except (ValueError, OSError) as error:
            diagnostic = _write_diagnostic(
                diagnostics,
                token,
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-fabric-reconciliation-diagnostic",
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

        validated = _validated_range_ledger(state_root, runs_root, ledger_path, ledger)
        if validated is None:
            # This reconciler owns only S5/S6 Range ledgers. Other Provider ledgers are untouched.
            if ledger.get("rangeId") not in _SUPPORTED_RANGES:
                continue
            diagnostic = _write_diagnostic(
                diagnostics,
                token,
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-fabric-reconciliation-diagnostic",
                    "decision": "attention-required",
                    "reason": "unsafe-range-ledger",
                    "ledgerPath": str(ledger_path),
                },
            )
            results.append(
                {
                    "runToken": token,
                    "decision": "attention-required",
                    "reason": "unsafe-range-ledger",
                    "diagnosticPath": str(diagnostic),
                }
            )
            continue

        run_path, namespace_candidates, host_link_candidates, canary_path = validated
        managed_tokens.add(token)
        if _identity_alive(ledger.get("ownerPid"), ledger.get("ownerStartTime")):
            results.append(
                {
                    "runToken": token,
                    "decision": "skipped-active",
                    "phase": ledger.get("phase"),
                    "topologyPhase": ledger.get("topologyPhase"),
                }
            )
            continue

        peer_closed = _terminate_from_ledger(
            ledger,
            pid_key="peerPid",
            start_key="peerStartTime",
            expected_fragment="python",
        )
        capture_closed = _terminate_from_ledger(
            ledger,
            pid_key="capturePid",
            start_key="captureStartTime",
            expected_fragment="tcpdump",
        )
        qemu_closed = _terminate_from_ledger(
            ledger,
            pid_key="qemuPid",
            start_key="qemuStartTime",
            expected_fragment="qemu-system-x86_64",
        )
        swtpm_closed = _terminate_from_ledger(
            ledger,
            pid_key="swtpmPid",
            start_key="swtpmStartTime",
            expected_fragment="swtpm",
        )
        requested_namespaces: list[str] = []
        residual_namespaces = list(namespace_candidates)
        requested_host_links: list[str] = []
        residual_host_links = list(host_link_candidates)
        if peer_closed and capture_closed and qemu_closed and swtpm_closed:
            requested_host_links, residual_host_links = _remove_host_links(
                ip_path, host_link_candidates
            )
            requested_namespaces, residual_namespaces = _remove_namespaces(
                ip_path, namespace_candidates
            )
            residual_host_links = sorted(_root_link_kinds(ip_path, host_link_candidates))

        clean_processes = peer_closed and capture_closed and qemu_closed and swtpm_closed
        clean_namespaces = not residual_namespaces
        clean_host_links = not residual_host_links
        if clean_processes and clean_namespaces and clean_host_links:
            if run_path.exists():
                shutil.rmtree(run_path)
            ledger_path.unlink(missing_ok=True)
            _fsync_directory(ledgers_root)
            canary_removed = True
            if canary_path is not None:
                canary_path.unlink(missing_ok=True)
                canary_removed = not canary_path.exists()
                canaries_root = canary_path.parent
                if canaries_root.exists() and not any(canaries_root.iterdir()):
                    canaries_root.rmdir()
            results.append(
                {
                    "runToken": token,
                    "decision": "reconciled",
                    "rangeId": ledger.get("rangeId"),
                    "phase": ledger.get("phase"),
                    "topologyPhase": ledger.get("topologyPhase"),
                    "peerClosed": peer_closed,
                    "captureClosed": capture_closed,
                    "qemuClosed": qemu_closed,
                    "swtpmClosed": swtpm_closed,
                    "requestedNamespaces": cast(list[JsonValue], requested_namespaces),
                    "residualNamespaces": cast(list[JsonValue], residual_namespaces),
                    "requestedHostLinks": cast(list[JsonValue], requested_host_links),
                    "residualHostLinks": cast(list[JsonValue], residual_host_links),
                    "runDirectoryRemoved": not run_path.exists(),
                    "ledgerRemoved": not ledger_path.exists(),
                    "canaryRemoved": canary_removed,
                }
            )
            continue

        diagnostic = _write_diagnostic(
            diagnostics,
            token,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.windows-fabric-reconciliation-diagnostic",
                "decision": "attention-required",
                "reason": "resource-identity-unresolved",
                "ledgerPath": str(ledger_path),
                "peerClosed": peer_closed,
                "captureClosed": capture_closed,
                "qemuClosed": qemu_closed,
                "swtpmClosed": swtpm_closed,
                "residualNamespaces": cast(list[JsonValue], residual_namespaces),
                "residualHostLinks": cast(list[JsonValue], residual_host_links),
            },
        )
        results.append(
            {
                "runToken": token,
                "decision": "attention-required",
                "reason": "resource-identity-unresolved",
                "diagnosticPath": str(diagnostic),
            }
        )

    for run_path in sorted(path for path in runs_root.iterdir() if path.is_dir()):
        if run_path.name in managed_tokens:
            continue
        ledger_path = ledgers_root / f"{run_path.name}.json"
        if ledger_path.exists():
            continue
        if run_path.name.startswith(("s5-", "s6-")):
            diagnostic = _write_diagnostic(
                diagnostics,
                run_path.name,
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-fabric-reconciliation-diagnostic",
                    "decision": "attention-required",
                    "reason": "range-run-directory-without-ledger",
                    "runPath": str(run_path),
                },
            )
            results.append(
                {
                    "runToken": run_path.name,
                    "decision": "attention-required",
                    "reason": "range-run-directory-without-ledger",
                    "diagnosticPath": str(diagnostic),
                }
            )

    attention = sum(item.get("decision") == "attention-required" for item in results)
    payload: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.windows-fabric-reconciliation-receipt",
        "recordedAtNs": time.time_ns(),
        "stateRoot": str(state_root),
        "results": cast(list[JsonValue], results),
        "reconciled": sum(item.get("decision") == "reconciled" for item in results),
        "skippedActive": sum(item.get("decision") == "skipped-active" for item in results),
        "attentionRequired": attention,
        "status": "passed" if attention == 0 else "attention-required",
    }
    if receipt_path is None:
        receipt_path = receipts_root / f"windows-fabric-reconcile-{time.time_ns()}.json"
    _replace_private_json(receipt_path, payload)
    return payload
