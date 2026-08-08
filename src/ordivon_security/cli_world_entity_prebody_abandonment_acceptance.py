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
    DESTINATION_WORLD,
    MIGRATION_ID,
    SOURCE_WORLD,
    _cleanup,
    _destination,
    _identity_alive,
    _machine_config,
    _read_object,
    _reconcile_request,
    _request,
    _source_revision,
    _write_json,
)
from ordivon_security.world_boundary import WorldEntityKvmConfig, WorldEntityKvmDestination
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineConfig,
    WindowsKvmMachineProvider,
)

_FAULT_PHASES = ("migration-staged", "swtpm-started", "qemu-launch-evidence")


class _PauseAfterPhaseProvider(WindowsKvmMachineProvider):
    def __init__(
        self,
        config: WindowsKvmMachineConfig,
        *,
        gate_path: Path,
        fault_phase: str,
    ) -> None:
        super().__init__(config)
        if fault_phase not in _FAULT_PHASES:
            raise ValueError(f"unsupported pre-body fault phase: {fault_phase}")
        self.gate_path = gate_path
        self.fault_phase = fault_phase

    def _pause(self, state: JsonObject) -> None:
        ledger_path = Path(str(state["runStatePath"]))
        ledger = _read_object(ledger_path, "Entity pre-body fault ledger")
        _write_json(
            self.gate_path,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.world-entity-prebody-fault-gate",
                "faultPhase": self.fault_phase,
                "ledgerPhase": ledger.get("phase"),
                "controllerPid": os.getpid(),
                "ledgerDigest": canonical_digest(ledger),
                "ownerPid": ledger.get("ownerPid"),
                "ownerStartTime": ledger.get("ownerStartTime"),
                "qemuPid": ledger.get("qemuPid"),
                "qemuStartTime": ledger.get("qemuStartTime"),
                "swtpmPid": ledger.get("swtpmPid"),
                "swtpmStartTime": ledger.get("swtpmStartTime"),
            },
        )
        while True:
            time.sleep(1)

    def persist_state(
        self,
        *,
        instance_id: str,
        generation: str,
        state: JsonObject,
        phase: str,
        extra: JsonObject | None = None,
    ) -> None:
        super().persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase=phase,
            extra=extra,
        )
        if phase == self.fault_phase:
            self._pause(state)

    def start_qemu(
        self,
        *,
        instance_id: str,
        generation: str,
        state: JsonObject,
        arguments: list[str],
        stdout_path: Path,
        stderr_path: Path,
        ledger_extra: JsonObject | None = None,
        network_namespace: str | None = None,
        ip_path: Path = Path("/usr/bin/ip"),
    ) -> subprocess.Popen[bytes]:
        if self.fault_phase != "qemu-launch-evidence":
            return super().start_qemu(
                instance_id=instance_id,
                generation=generation,
                state=state,
                arguments=arguments,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                ledger_extra=ledger_extra,
                network_namespace=network_namespace,
                ip_path=ip_path,
            )
        run_path = Path(str(state["runPath"]))
        for path in (stdout_path, stderr_path):
            if path.parent != run_path or path.exists() or path.is_symlink():
                raise RuntimeError("invalid QEMU launch-evidence path")
            path.touch(exist_ok=False)
        self._pause(state)
        raise AssertionError("unreachable after pre-body fault pause")


def _child(args: argparse.Namespace) -> int:
    request = _read_object(args.request_file, "Entity pre-body request")
    machine = _machine_config(args.state_root, args.base_manifest, memory_mib=args.memory_mib)
    provider = _PauseAfterPhaseProvider(
        machine,
        gate_path=args.gate,
        fault_phase=args.fault_phase,
    )
    destination = WorldEntityKvmDestination(
        WorldEntityKvmConfig(
            machine=machine,
            destination_world_id=DESTINATION_WORLD,
            allowed_source_world_ids=(SOURCE_WORLD,),
        ),
        machine_provider=provider,
    )
    destination.handle(request)
    return 2


def _wait_for_gate(
    process: subprocess.Popen[str],
    gate_path: Path,
    *,
    timeout_seconds: int,
) -> JsonObject:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if gate_path.exists():
            return _read_object(gate_path, "Entity pre-body fault gate")
        return_code = process.poll()
        if return_code is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise RuntimeError(
                "Entity pre-body child exited before fault gate: "
                f"code={return_code} stdout={stdout[-1000:]} stderr={stderr[-1000:]}"
            )
        time.sleep(0.1)
    raise TimeoutError("Entity pre-body child did not reach the requested fault phase")


def _run_case(
    *,
    fault_phase: str,
    state_root: Path,
    base_manifest: Path,
    memory_mib: int,
    timeout_seconds: int,
) -> JsonObject:
    if state_root.exists():
        raise RuntimeError(f"refusing existing pre-body acceptance root: {state_root}")
    request = _request()
    request_file = state_root.parent / f".{state_root.name}.request.json"
    gate_path = state_root.parent / f".{state_root.name}.gate.json"
    _write_json(request_file, request)
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ordivon_security.cli_world_entity_prebody_abandonment_acceptance",
                "--child",
                "--fault-phase",
                fault_phase,
                "--state-root",
                str(state_root),
                "--base-manifest",
                str(base_manifest),
                "--request-file",
                str(request_file),
                "--gate",
                str(gate_path),
                "--memory-mib",
                str(memory_mib),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        gate = _wait_for_gate(process, gate_path, timeout_seconds=timeout_seconds)
        if gate.get("faultPhase") != fault_phase:
            raise RuntimeError("pre-body fault gate reported another phase")
        ledger_paths = sorted((state_root / "run-ledgers").glob("*.json"))
        if len(ledger_paths) != 1:
            raise RuntimeError("pre-body fault did not retain exactly one ledger")
        ledger_path = ledger_paths[0]
        ledger_before = ledger_path.read_bytes()
        ledger = _read_object(ledger_path, "pre-body pre-kill ledger")
        ledger_stable_before_kill = ledger_path.read_bytes() == ledger_before
        expected_ledger_phase = (
            "swtpm-started" if fault_phase == "qemu-launch-evidence" else fault_phase
        )
        if gate.get("ledgerPhase") != expected_ledger_phase:
            raise RuntimeError("pre-body gate ledger phase differs from expected fault state")
        if ledger.get("phase") != expected_ledger_phase:
            raise RuntimeError("pre-body ledger phase differs from expected fault state")
        if ledger.get("qemuPid") not in {0, None} or ledger.get("qemuStartTime") is not None:
            raise RuntimeError("QEMU body exists at a declared pre-body fault gate")
        run_path = Path(str(ledger["runPath"]))
        qemu_launch_evidence = any(
            (run_path / name).exists()
            for name in ("qmp.sock", "qemu.stdout.log", "qemu.stderr.log")
        )
        if fault_phase == "qemu-launch-evidence":
            if not qemu_launch_evidence:
                raise RuntimeError("ambiguous QEMU fault lacks launch evidence")
        elif qemu_launch_evidence:
            raise RuntimeError("QEMU launch evidence exists at a safe pre-body fault gate")

        swtpm_alive_before = _identity_alive(
            ledger.get("swtpmPid"), ledger.get("swtpmStartTime")
        )
        if fault_phase == "migration-staged" and swtpm_alive_before:
            raise RuntimeError("staged fault unexpectedly has a live swtpm process")
        if fault_phase != "migration-staged" and not swtpm_alive_before:
            raise RuntimeError("post-TPM fault did not retain the exact swtpm process")

        os.kill(process.pid, signal.SIGKILL)
        child_return_code = process.wait(timeout=10)
        swtpm_survived_controller = _identity_alive(
            ledger.get("swtpmPid"), ledger.get("swtpmStartTime")
        )
        if fault_phase != "migration-staged" and not swtpm_survived_controller:
            raise RuntimeError("swtpm did not survive controller SIGKILL")

        destination = _destination(state_root, base_manifest, memory_mib=memory_mib)
        identity = destination.execution_identity
        if identity.get("revision") != "4":
            raise RuntimeError("pre-body acceptance is not using Entity recovery revision 4")
        response = destination.handle(_reconcile_request(request))
        receipt_absent = not destination._receipt_path(MIGRATION_ID).exists()

        if fault_phase == "qemu-launch-evidence":
            if response.get("status") != "unknown":
                raise RuntimeError("ambiguous QEMU launch evidence was not kept UNKNOWN")
            if response.get("reason") != "unresolved-native-materialization:qemu":
                raise RuntimeError("ambiguous QEMU launch returned the wrong UNKNOWN reason")
            if not run_path.exists() or not ledger_path.exists() or not receipt_absent:
                raise RuntimeError("UNKNOWN pre-body state was mutated before explicit cleanup")
            cleanup = _cleanup(destination, request)
            if cleanup.get("clean") is not True:
                raise RuntimeError("acceptance cleanup failed after the UNKNOWN proof")
            response_evidence: dict[str, object] = {}
        else:
            if response.get("status") != "not_committed":
                raise RuntimeError("safe pre-body reconcile did not prove NOT_COMMITTED")
            raw_evidence = response.get("evidence")
            if not isinstance(raw_evidence, dict):
                raise RuntimeError("pre-body NOT_COMMITTED response lacks evidence")
            response_evidence = raw_evidence
            if (
                response_evidence.get("abandonedPreBodyCompensated") is not True
                or response_evidence.get("abandonedPhase") != fault_phase
                or response_evidence.get("predecessorOwnerDead") is not True
                or response_evidence.get("zeroResidualsObserved") is not True
                or response_evidence.get("exactOriginalRetrySafe") is not True
            ):
                raise RuntimeError("pre-body reconcile evidence does not justify exact retry")

        run_removed = not run_path.exists()
        ledger_removed = not ledger_path.exists()
        swtpm_closed = not _identity_alive(
            ledger.get("swtpmPid"), ledger.get("swtpmStartTime")
        )
        if not run_removed or not ledger_removed or not swtpm_closed or not receipt_absent:
            raise RuntimeError("pre-body acceptance did not converge to zero residuals")

        return {
            "faultPhase": fault_phase,
            "ledgerPhase": expected_ledger_phase,
            "controllerLoss": {
                "signal": "SIGKILL",
                "childReturnCode": child_return_code,
                "predecessorOwnerMatchedController": (
                    ledger.get("ownerPid") == gate.get("controllerPid")
                ),
            },
            "nativeBeforeKill": {
                "qemuBodyAbsent": True,
                "qemuLaunchEvidence": qemu_launch_evidence,
                "swtpmAlive": swtpm_alive_before,
                "ledgerDigest": canonical_digest(ledger),
                "ledgerBytesStableUntilKill": ledger_stable_before_kill,
            },
            "afterControllerLoss": {
                "swtpmSurvived": swtpm_survived_controller,
            },
            "freshReconcile": {
                "status": response.get("status"),
                "reason": response.get("reason"),
                "exactOriginalRetrySafe": response_evidence.get("exactOriginalRetrySafe", False),
                "abandonedPreBodyCompensated": response_evidence.get(
                    "abandonedPreBodyCompensated", False
                ),
                "zeroResidualsObserved": response_evidence.get("zeroResidualsObserved", False),
                "receiptAbsent": receipt_absent,
            },
            "closure": {
                "runDirectoryRemoved": run_removed,
                "ledgerRemoved": ledger_removed,
                "swtpmClosed": swtpm_closed,
            },
        }
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        request_file.unlink(missing_ok=True)
        gate_path.unlink(missing_ok=True)
        if state_root.exists():
            shutil.rmtree(state_root, ignore_errors=True)


def _parent(args: argparse.Namespace) -> int:
    root = args.state_root_base
    root.parent.mkdir(parents=True, exist_ok=True)
    cases: list[JsonObject] = []
    for suffix, fault_phase in (
        ("staged", "migration-staged"),
        ("tpm", "swtpm-started"),
        ("qemu", "qemu-launch-evidence"),
    ):
        state_root = root.with_name(f"{root.name}-{suffix}")
        cases.append(
            _run_case(
                fault_phase=fault_phase,
                state_root=state_root,
                base_manifest=args.base_manifest,
                memory_mib=args.memory_mib,
                timeout_seconds=args.timeout_seconds,
            )
        )
    evidence: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.world-entity-prebody-abandonment-acceptance",
        "status": "passed",
        "sourceRevision": _source_revision(),
        "migrationId": MIGRATION_ID,
        "cases": cast(list[object], cases),
    }
    if args.output is not None:
        _write_json(args.output, evidence)
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Physical World Entity pre-body abandonment acceptance"
    )
    parser.add_argument("--state-root-base", type=Path, default=Path("/tmp/oe-prebody"))
    parser.add_argument("--state-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=768)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--fault-phase", choices=_FAULT_PHASES, help=argparse.SUPPRESS)
    parser.add_argument("--request-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--gate", type=Path, help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.child:
        if args.state_root is None or args.request_file is None or args.gate is None:
            raise SystemExit("child mode requires state root, request file, and gate")
        if args.fault_phase is None:
            raise SystemExit("child mode requires a fault phase")
        return _child(args)
    return _parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
