from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.cli_world_entity_controller_loss_acceptance import (
    MIGRATION_ID,
    _cleanup,
    _destination,
    _identity_alive,
    _machine_config,
    _read_object,
    _reconcile_request,
    _request,
    _source_revision,
    _wait_for_gate,
    _write_json,
)
from ordivon_security.world_boundary import WorldEntityKvmDestination
from ordivon_security.providers.windows_kvm import WindowsKvmMachineProvider


def _wait_for_files(
    paths: tuple[Path, ...],
    processes: tuple[subprocess.Popen[str], ...],
    *,
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if all(path.exists() for path in paths):
            return
        for process in processes:
            return_code = process.poll()
            if return_code is not None:
                stdout, stderr = process.communicate(timeout=1)
                raise RuntimeError(
                    "publication child exited before readiness: "
                    f"code={return_code} stdout={stdout[-1000:]} stderr={stderr[-1000:]}"
                )
        time.sleep(0.05)
    raise TimeoutError("publication children did not reach readiness")


class _PublicationProbeProvider(WindowsKvmMachineProvider):
    def __init__(self, config, *, publication_marker: Path | None = None) -> None:
        super().__init__(config)
        self.publication_marker = publication_marker

    def persist_state(self, *, instance_id, generation, state, phase, extra=None) -> None:
        if phase == "migration-running-contained" and self.publication_marker is not None:
            _write_json(
                self.publication_marker,
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.world-entity-publication-attempt",
                    "publisherPid": os.getpid(),
                    "predecessorOwnerPid": state.get("ownerPid"),
                    "predecessorOwnerStartTime": state.get("ownerStartTime"),
                },
            )
        super().persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase=phase,
            extra=extra,
        )

    def start_swtpm(self, *args, **kwargs):
        raise RuntimeError("publication recovery must not start swtpm")

    def start_qemu(self, *args, **kwargs):
        raise RuntimeError("publication recovery must not start QEMU")


class _PauseAfterStablePublicationProvider(_PublicationProbeProvider):
    def __init__(self, config, *, publication_gate: Path) -> None:
        super().__init__(config)
        self.publication_gate = publication_gate

    def persist_state(self, *, instance_id, generation, state, phase, extra=None) -> None:
        super().persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase=phase,
            extra=extra,
        )
        if phase == "migration-running-contained":
            ledger_path = Path(str(state["runStatePath"]))
            ledger = _read_object(ledger_path, "post-publication Entity ledger")
            _write_json(
                self.publication_gate,
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.world-entity-publication-gate",
                    "publisherPid": os.getpid(),
                    "ledgerPhase": ledger.get("phase"),
                    "ledgerDigest": canonical_digest(ledger),
                    "ownerPid": ledger.get("ownerPid"),
                    "ownerStartTime": ledger.get("ownerStartTime"),
                },
            )
            while True:
                time.sleep(1)


def _launch_initial_controller(
    args: argparse.Namespace,
    request_file: Path,
    gate: Path,
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_world_entity_controller_loss_acceptance",
            "--child",
            "--state-root",
            str(args.state_root),
            "--base-manifest",
            str(args.base_manifest),
            "--request-file",
            str(request_file),
            "--gate",
            str(gate),
            "--memory-mib",
            str(args.memory_mib),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _prepare_dead_owner(
    args: argparse.Namespace,
    request: JsonObject,
    request_file: Path,
    gate: Path,
) -> tuple[Path, JsonObject, int]:
    controller = _launch_initial_controller(args, request_file, gate)
    try:
        gate_value = _wait_for_gate(controller, gate, timeout_seconds=args.timeout_seconds)
        if gate_value.get("ledgerPhase") != "executing":
            raise RuntimeError("initial controller did not stop at executing")
        if gate_value.get("networkDevicePresent") is not False:
            raise RuntimeError("initial Entity carrier unexpectedly has a network device")
        ledger_paths = sorted((args.state_root / "run-ledgers").glob("*.json"))
        if len(ledger_paths) != 1:
            raise RuntimeError("initial Entity carrier did not retain exactly one ledger")
        ledger_path = ledger_paths[0]
        ledger = _read_object(ledger_path, "initial Entity ledger")
        if not _identity_alive(ledger.get("qemuPid"), ledger.get("qemuStartTime")):
            raise RuntimeError("initial QEMU is not alive")
        if not _identity_alive(ledger.get("swtpmPid"), ledger.get("swtpmStartTime")):
            raise RuntimeError("initial swtpm is not alive")
        os.kill(controller.pid, signal.SIGKILL)
        return_code = controller.wait(timeout=10)
        if not _identity_alive(ledger.get("qemuPid"), ledger.get("qemuStartTime")):
            raise RuntimeError("QEMU did not survive original controller SIGKILL")
        if not _identity_alive(ledger.get("swtpmPid"), ledger.get("swtpmStartTime")):
            raise RuntimeError("swtpm did not survive original controller SIGKILL")
        return ledger_path, ledger, return_code
    finally:
        if controller.poll() is None:
            controller.kill()
            controller.wait(timeout=10)


def _reconcile_child(args: argparse.Namespace) -> int:
    if args.request_file is None or args.result is None:
        raise SystemExit("reconcile child requires --request-file and --result")
    request = _read_object(args.request_file, "publication reconcile request")
    machine = _machine_config(args.state_root, args.base_manifest, memory_mib=args.memory_mib)
    if args.pause_after_stable:
        if args.publication_gate is None:
            raise SystemExit("pause-after-stable requires --publication-gate")
        provider: WindowsKvmMachineProvider = _PauseAfterStablePublicationProvider(
            machine,
            publication_gate=args.publication_gate,
        )
    else:
        provider = _PublicationProbeProvider(
            machine,
            publication_marker=args.publication_marker,
        )
    destination = _destination(
        args.state_root,
        args.base_manifest,
        memory_mib=args.memory_mib,
        provider=provider,
    )
    if destination.execution_identity.get("revision") != "3":
        raise RuntimeError("publication recovery acceptance requires Entity revision 3")
    if args.ready is not None:
        _write_json(
            args.ready,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.world-entity-publication-child-ready",
                "pid": os.getpid(),
            },
        )
    if args.release is not None:
        deadline = time.monotonic() + args.timeout_seconds
        while not args.release.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("publication reconcile child was not released")
            time.sleep(0.05)
    response = destination.handle(_reconcile_request(request))
    _write_json(args.result, cast(JsonObject, response))
    return 0


def _launch_reconciler(
    args: argparse.Namespace,
    *,
    request_file: Path,
    result: Path,
    ready: Path | None = None,
    release: Path | None = None,
    marker: Path | None = None,
    pause_after_stable: bool = False,
    publication_gate: Path | None = None,
) -> subprocess.Popen[str]:
    command = [
        sys.executable,
        "-m",
        "ordivon_security.cli_world_entity_publication_recovery_acceptance",
        "--reconcile-child",
        "--scenario",
        args.scenario,
        "--state-root",
        str(args.state_root),
        "--base-manifest",
        str(args.base_manifest),
        "--request-file",
        str(request_file),
        "--result",
        str(result),
        "--memory-mib",
        str(args.memory_mib),
        "--timeout-seconds",
        str(args.timeout_seconds),
    ]
    for flag, path in (
        ("--ready", ready),
        ("--release", release),
        ("--publication-marker", marker),
        ("--publication-gate", publication_gate),
    ):
        if path is not None:
            command.extend([flag, str(path)])
    if pause_after_stable:
        command.append("--pause-after-stable")
    return subprocess.Popen(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _wait_success(process: subprocess.Popen[str], label: str, *, timeout_seconds: int) -> None:
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        raise TimeoutError(f"{label} did not terminate") from None
    if return_code != 0:
        stdout, stderr = process.communicate(timeout=1)
        raise RuntimeError(
            f"{label} failed: code={return_code} stdout={stdout[-1000:]} stderr={stderr[-1000:]}"
        )


def _run_race(
    args: argparse.Namespace,
    request: JsonObject,
    request_file: Path,
    ledger_path: Path,
    predecessor: JsonObject,
) -> JsonObject:
    root = args.state_root.parent
    suffix = args.state_root.name
    ready_a = root / f".{suffix}.pub-a.ready.json"
    ready_b = root / f".{suffix}.pub-b.ready.json"
    release = root / f".{suffix}.publish.release.json"
    result_a = root / f".{suffix}.pub-a.result.json"
    result_b = root / f".{suffix}.pub-b.result.json"
    marker_a = root / f".{suffix}.pub-a.marker.json"
    marker_b = root / f".{suffix}.pub-b.marker.json"
    paths = (ready_a, ready_b, release, result_a, result_b, marker_a, marker_b)
    processes: tuple[subprocess.Popen[str], subprocess.Popen[str]] | None = None
    try:
        process_a = _launch_reconciler(
            args,
            request_file=request_file,
            result=result_a,
            ready=ready_a,
            release=release,
            marker=marker_a,
        )
        process_b = _launch_reconciler(
            args,
            request_file=request_file,
            result=result_b,
            ready=ready_b,
            release=release,
            marker=marker_b,
        )
        processes = (process_a, process_b)
        _wait_for_files((ready_a, ready_b), processes, timeout_seconds=args.timeout_seconds)
        _write_json(
            release,
            {"schemaVersion": 1, "kind": "ordivon.security.world-entity-publication-release"},
        )
        _wait_success(process_a, "publisher A", timeout_seconds=args.timeout_seconds)
        _wait_success(process_b, "publisher B", timeout_seconds=args.timeout_seconds)
        response_a = _read_object(result_a, "publisher A response")
        response_b = _read_object(result_b, "publisher B response")
        markers = [path for path in (marker_a, marker_b) if path.exists()]
        ledger = _read_object(ledger_path, "post-race Entity ledger")
        destination = _destination(
            args.state_root,
            args.base_manifest,
            memory_mib=args.memory_mib,
        )
        receipt_present = destination._receipt_path(MIGRATION_ID).is_file()
        qemu_alive = _identity_alive(ledger.get("qemuPid"), ledger.get("qemuStartTime"))
        swtpm_alive = _identity_alive(ledger.get("swtpmPid"), ledger.get("swtpmStartTime"))
        passed = all(
            (
                response_a.get("status") == "materialized",
                response_b.get("status") == "materialized",
                response_a == response_b,
                len(markers) == 1,
                ledger.get("phase") == "migration-running-contained",
                ledger.get("ownerPid") == predecessor.get("ownerPid"),
                ledger.get("ownerStartTime") == predecessor.get("ownerStartTime"),
                receipt_present,
                qemu_alive,
                swtpm_alive,
            )
        )
        if not passed:
            raise RuntimeError("competing Entity publishers did not serialize to one publication")
        return {
            "publisherResponsesEqual": True,
            "materializedResponses": 2,
            "stablePublicationAttempts": len(markers),
            "stablePhase": ledger.get("phase"),
            "predecessorOwnerPreserved": True,
            "receiptPresent": receipt_present,
            "qemuIdentityPreserved": qemu_alive,
            "swtpmIdentityPreserved": swtpm_alive,
            "physicalBodyReplay": False,
        }
    finally:
        if processes is not None:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        for path in paths:
            path.unlink(missing_ok=True)


def _run_publisher_crash(
    args: argparse.Namespace,
    request: JsonObject,
    request_file: Path,
    ledger_path: Path,
    predecessor: JsonObject,
) -> JsonObject:
    root = args.state_root.parent
    suffix = args.state_root.name
    first_result = root / f".{suffix}.first-publisher.result.json"
    stable_gate = root / f".{suffix}.stable-publication.gate.json"
    second_result = root / f".{suffix}.second-publisher.result.json"
    second_marker = root / f".{suffix}.second-publisher.marker.json"
    paths = (first_result, stable_gate, second_result, second_marker)
    first: subprocess.Popen[str] | None = None
    second: subprocess.Popen[str] | None = None
    try:
        first = _launch_reconciler(
            args,
            request_file=request_file,
            result=first_result,
            pause_after_stable=True,
            publication_gate=stable_gate,
        )
        _wait_for_files((stable_gate,), (first,), timeout_seconds=args.timeout_seconds)
        stable_before_kill = ledger_path.read_bytes()
        stable_ledger = _read_object(ledger_path, "first publisher stable ledger")
        destination = _destination(
            args.state_root,
            args.base_manifest,
            memory_mib=args.memory_mib,
        )
        receipt_path = destination._receipt_path(MIGRATION_ID)
        if stable_ledger.get("phase") != "migration-running-contained":
            raise RuntimeError("first publisher did not persist stable phase before gate")
        if receipt_path.exists():
            raise RuntimeError("first publisher committed receipt before crash gate")
        os.kill(first.pid, signal.SIGKILL)
        first_return_code = first.wait(timeout=10)
        if not _identity_alive(
            stable_ledger.get("qemuPid"), stable_ledger.get("qemuStartTime")
        ):
            raise RuntimeError("QEMU did not survive publication successor SIGKILL")
        if not _identity_alive(
            stable_ledger.get("swtpmPid"), stable_ledger.get("swtpmStartTime")
        ):
            raise RuntimeError("swtpm did not survive publication successor SIGKILL")

        second = _launch_reconciler(
            args,
            request_file=request_file,
            result=second_result,
            marker=second_marker,
        )
        _wait_success(second, "second publisher", timeout_seconds=args.timeout_seconds)
        response = _read_object(second_result, "second publisher response")
        ledger_after = ledger_path.read_bytes()
        after = _read_object(ledger_path, "post-second-publisher Entity ledger")
        qemu_alive = _identity_alive(after.get("qemuPid"), after.get("qemuStartTime"))
        swtpm_alive = _identity_alive(after.get("swtpmPid"), after.get("swtpmStartTime"))
        passed = all(
            (
                first_return_code == -signal.SIGKILL,
                response.get("status") == "materialized",
                ledger_after == stable_before_kill,
                not second_marker.exists(),
                receipt_path.is_file(),
                after.get("ownerPid") == predecessor.get("ownerPid"),
                after.get("ownerStartTime") == predecessor.get("ownerStartTime"),
                qemu_alive,
                swtpm_alive,
            )
        )
        if not passed:
            raise RuntimeError("second Entity publisher did not recover stable publication exactly")
        return {
            "firstPublisherExit": first_return_code,
            "firstPublisherStableLedger": True,
            "receiptAbsentAtFirstCrash": True,
            "secondResponse": response.get("status"),
            "secondStablePublicationAttempt": second_marker.exists(),
            "stableLedgerBytesUnchanged": ledger_after == stable_before_kill,
            "receiptReconstructed": receipt_path.is_file(),
            "predecessorOwnerPreserved": True,
            "qemuIdentityPreserved": qemu_alive,
            "swtpmIdentityPreserved": swtpm_alive,
            "physicalBodyReplay": False,
        }
    finally:
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        for path in paths:
            path.unlink(missing_ok=True)


def _parent(args: argparse.Namespace) -> int:
    if args.state_root.exists():
        raise SystemExit(f"refusing existing acceptance state root: {args.state_root}")
    args.state_root.parent.mkdir(parents=True, exist_ok=True)
    request = _request()
    root = args.state_root.parent
    suffix = args.state_root.name
    request_file = root / f".{suffix}.request.json"
    initial_gate = root / f".{suffix}.initial.gate.json"
    _write_json(request_file, request)
    destination: WorldEntityKvmDestination | None = None
    cleanup: dict[str, object] | None = None
    try:
        ledger_path, predecessor, controller_return_code = _prepare_dead_owner(
            args,
            request,
            request_file,
            initial_gate,
        )
        destination = _destination(
            args.state_root,
            args.base_manifest,
            memory_mib=args.memory_mib,
        )
        if destination.execution_identity.get("revision") != "3":
            raise RuntimeError("publication recovery acceptance requires Entity revision 3")
        if args.scenario == "race":
            scenario_result = _run_race(
                args,
                request,
                request_file,
                ledger_path,
                predecessor,
            )
        else:
            scenario_result = _run_publisher_crash(
                args,
                request,
                request_file,
                ledger_path,
                predecessor,
            )
        cleanup = _cleanup(destination, request)
        if not cleanup.get("clean"):
            raise RuntimeError("publication recovery acceptance did not close cleanly")
        evidence: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.world-entity-publication-recovery-acceptance",
            "status": "passed",
            "sourceRevision": _source_revision(),
            "scenario": args.scenario,
            "migrationId": MIGRATION_ID,
            "planDigest": request["planDigest"],
            "originalControllerExit": controller_return_code,
            "scenarioResult": scenario_result,
            "cleanup": {
                "clean": cleanup.get("clean"),
                "qemuClosed": cleanup.get("qemuClosed"),
                "swtpmClosed": cleanup.get("swtpmClosed"),
                "runDirectoryRemoved": cleanup.get("runDirectoryRemoved"),
                "ledgerRemoved": cleanup.get("ledgerRemoved"),
            },
        }
        if args.output is not None:
            _write_json(args.output, evidence)
        print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        if destination is not None and cleanup is None:
            try:
                if list((args.state_root / "run-ledgers").glob("*.json")):
                    _cleanup(destination, request)
            except Exception:
                pass
        request_file.unlink(missing_ok=True)
        initial_gate.unlink(missing_ok=True)
        if args.state_root.exists():
            shutil.rmtree(args.state_root, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="World Entity publication recovery acceptance")
    parser.add_argument("--scenario", choices=("race", "publisher-crash"), required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=768)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--reconcile-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--request-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--result", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--ready", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--release", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--publication-marker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--pause-after-stable", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--publication-gate", type=Path, help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.reconcile_child:
        return _reconcile_child(args)
    return _parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
