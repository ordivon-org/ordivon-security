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
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineConfig,
    WindowsKvmMachineProvider,
    _process_start_time,
)
from ordivon_security.world_boundary import WorldEntityKvmConfig, WorldEntityKvmDestination

SOURCE_WORLD = "run:world-entity-controller-loss:source"
DESTINATION_WORLD = "security-world:world-entity-controller-loss:destination"
MIGRATION_ID = "migration:world-entity-controller-loss:1"
ENTITY_ID = "entity:world-entity-controller-loss:agent"


def _machine_config(
    state_root: Path,
    base_manifest: Path,
    *,
    memory_mib: int,
) -> WindowsKvmMachineConfig:
    return WindowsKvmMachineConfig(
        state_root=state_root,
        base_manifest_path=base_manifest,
        qemu_path=Path("/usr/bin/qemu-system-x86_64"),
        qemu_img_path=Path("/usr/bin/qemu-img"),
        swtpm_path=Path("/usr/bin/swtpm"),
        setpriv_path=Path("/usr/bin/setpriv"),
        firmware_code_path=Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
        run_user="qemu",
        run_group="qemu",
        memory_mib=memory_mib,
        vcpu_count=1,
        qmp_ready_timeout_seconds=60,
        shutdown_grace_seconds=15,
    )


def _request() -> JsonObject:
    source_occurrence: JsonObject = {
        "factId": "fact:world-entity-controller-loss:departure",
        "verified": True,
    }
    departure: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.world.entity-departure-receipt",
        "migrationId": MIGRATION_ID,
        "entityId": ENTITY_ID,
        "sourceWorldId": SOURCE_WORLD,
        "destinationWorldId": DESTINATION_WORLD,
        "sourceOccurrenceId": "entity-departure:world-entity-controller-loss:1",
        "sourceOccurrenceDigest": canonical_digest(source_occurrence),
        "authority": {
            "authorityId": "acceptance:source-world",
            "mechanism": "deterministic-acceptance-source.v1",
            "evidence": source_occurrence,
        },
    }
    continuity: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.acceptance.entity-continuity",
        "entityId": ENTITY_ID,
        "identityRef": "agent-identity:world-entity-controller-loss",
        "cognitionRef": "agent-context:world-entity-controller-loss",
        "sourceWorldLocalStateCopied": False,
    }
    plan: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.world.prepared-entity-migration",
        "migrationId": MIGRATION_ID,
        "entityId": ENTITY_ID,
        "sourceWorldId": SOURCE_WORLD,
        "destinationWorldId": DESTINATION_WORLD,
        "sourceDepartureDigest": canonical_digest(departure),
        "continuityPayloadDigest": canonical_digest(continuity),
    }
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.entity-migration-destination-request",
        "operation": "materialize",
        "plan": plan,
        "planDigest": canonical_digest(plan),
        "sourceDeparture": departure,
        "continuityPayload": continuity,
    }


def _reconcile_request(request: JsonObject) -> JsonObject:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.entity-migration-destination-request",
        "operation": "reconcile",
        "plan": request["plan"],
        "planDigest": request["planDigest"],
    }


def _write_json(path: Path, value: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _read_object(path: Path, label: str) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RuntimeError(f"{label} is not a JSON object")
    return cast(JsonObject, value)


def _source_revision() -> str:
    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
        timeout=10,
    )
    return completed.stdout.strip()


class _PauseAfterQmpProvider(WindowsKvmMachineProvider):
    def __init__(self, config: WindowsKvmMachineConfig, *, gate_path: Path) -> None:
        super().__init__(config)
        self.gate_path = gate_path

    def inspect_qmp(self, state: JsonObject) -> JsonObject:
        result = super().inspect_qmp(state)
        ledger_path = Path(str(state["runStatePath"]))
        ledger = _read_object(ledger_path, "Entity controller-loss gate ledger")
        _write_json(
            self.gate_path,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.world-entity-controller-loss-gate",
                "controllerPid": os.getpid(),
                "ledgerPhase": ledger.get("phase"),
                "ownerPid": ledger.get("ownerPid"),
                "ownerStartTime": ledger.get("ownerStartTime"),
                "qemuPid": ledger.get("qemuPid"),
                "qemuStartTime": ledger.get("qemuStartTime"),
                "swtpmPid": ledger.get("swtpmPid"),
                "swtpmStartTime": ledger.get("swtpmStartTime"),
                "ledgerDigest": canonical_digest(ledger),
                "networkDevicePresent": result.get("networkDevicePresent"),
            },
        )
        while True:
            time.sleep(1)


def _destination(
    state_root: Path,
    base_manifest: Path,
    *,
    memory_mib: int,
    provider: WindowsKvmMachineProvider | None = None,
) -> WorldEntityKvmDestination:
    machine = _machine_config(state_root, base_manifest, memory_mib=memory_mib)
    return WorldEntityKvmDestination(
        WorldEntityKvmConfig(
            machine=machine,
            destination_world_id=DESTINATION_WORLD,
            allowed_source_world_ids=(SOURCE_WORLD,),
        ),
        machine_provider=provider,
    )


def _child(args: argparse.Namespace) -> int:
    request = _read_object(args.request_file, "Entity controller-loss request")
    machine = _machine_config(args.state_root, args.base_manifest, memory_mib=args.memory_mib)
    provider = _PauseAfterQmpProvider(machine, gate_path=args.gate)
    destination = _destination(
        args.state_root,
        args.base_manifest,
        memory_mib=args.memory_mib,
        provider=provider,
    )
    destination.handle(request)
    return 2


def _wait_for_gate(
    process: subprocess.Popen[str],
    gate: Path,
    *,
    timeout_seconds: int,
) -> JsonObject:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if gate.exists():
            return _read_object(gate, "Entity controller-loss gate")
        return_code = process.poll()
        if return_code is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise RuntimeError(
                "Entity materialization child exited before fault gate: "
                f"code={return_code} stdout={stdout[-1000:]} stderr={stderr[-1000:]}"
            )
        time.sleep(0.1)
    raise TimeoutError("Entity materialization child did not reach the QMP fault gate")


def _identity_alive(pid: object, start_time: object) -> bool:
    return (
        isinstance(pid, int)
        and pid > 0
        and isinstance(start_time, int)
        and _process_start_time(pid) == start_time
    )


def _process_command(pid: object) -> str:
    if not isinstance(pid, int) or pid < 1:
        return ""
    try:
        return (
            Path(f"/proc/{pid}/cmdline")
            .read_bytes()
            .replace(b"\0", b" ")
            .decode("utf-8", errors="replace")
        )
    except OSError:
        return ""


def _observe_unpublished_physical_state(
    destination: WorldEntityKvmDestination,
    request: JsonObject,
    ledger_path: Path,
    ledger_before: bytes,
) -> JsonObject:
    plan = cast(JsonObject, request["plan"])
    plan_digest = cast(str, request["planDigest"])
    observed = destination._observe_existing_state(plan, plan_digest)
    topology = destination.machine_provider.inspect_qmp(observed)
    block = destination.machine_provider.qmp_execute(observed, "query-block")
    run_disk = Path(str(observed["runPath"])) / "ordivon-migration.img"
    qemu_command = _process_command(observed.get("qemuPid"))
    block_text = json.dumps(block, sort_keys=True, separators=(",", ":"))
    status = topology.get("status")
    qmp_running = isinstance(status, dict) and status.get("running") is True
    command_binds_carrier = all(
        marker in qemu_command
        for marker in (
            str(run_disk),
            "id=migrationdisk",
            "usb-storage",
            "drive=migrationdisk",
            "serial=ORDIVON_MIG",
        )
    )
    block_binds_carrier = "migrationdisk" in block_text
    run_disk_present = run_disk.is_file() and not run_disk.is_symlink()
    ledger_unchanged = ledger_path.read_bytes() == ledger_before
    qemu_alive = _identity_alive(observed.get("qemuPid"), observed.get("qemuStartTime"))
    swtpm_alive = _identity_alive(observed.get("swtpmPid"), observed.get("swtpmStartTime"))
    no_network = topology.get("networkDevicePresent") is False
    completion_observable = all(
        (
            qemu_alive,
            swtpm_alive,
            qmp_running,
            no_network,
            run_disk_present,
            command_binds_carrier,
            block_binds_carrier,
            ledger_unchanged,
        )
    )
    return {
        "qemuAlive": qemu_alive,
        "swtpmAlive": swtpm_alive,
        "qmpRunning": qmp_running,
        "networkDevicePresent": topology.get("networkDevicePresent"),
        "runDiskPresent": run_disk_present,
        "qemuCommandBindsCarrier": command_binds_carrier,
        "qmpBlockBindsCarrier": block_binds_carrier,
        "ledgerBytesUnchanged": ledger_unchanged,
        "completedButUnpublishedObservable": completion_observable,
    }


def _cleanup(
    destination: WorldEntityKvmDestination,
    request: JsonObject,
) -> dict[str, object]:
    plan = cast(JsonObject, request["plan"])
    plan_digest = cast(str, request["planDigest"])
    observed = destination._observe_existing_state(plan, plan_digest)
    binding = destination._binding(plan, plan_digest)
    closure = destination.machine_provider.destroy_state(
        instance_id=cast(str, observed["instanceId"]),
        generation=cast(str, observed["generation"]),
        state=observed,
        ledger_extra=destination._ledger_extra(binding),
    )
    return {"clean": closure.clean, **closure.details}


def _parent(args: argparse.Namespace) -> int:
    if args.state_root.exists():
        raise SystemExit(f"refusing existing acceptance state root: {args.state_root}")
    args.state_root.parent.mkdir(parents=True, exist_ok=True)
    request = _request()
    request_file = args.state_root.parent / f".{args.state_root.name}.request.json"
    gate = args.state_root.parent / f".{args.state_root.name}.gate.json"
    _write_json(request_file, request)
    process: subprocess.Popen[str] | None = None
    destination: WorldEntityKvmDestination | None = None
    cleanup: dict[str, object] | None = None
    try:
        process = subprocess.Popen(
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
        gate_value = _wait_for_gate(process, gate, timeout_seconds=args.timeout_seconds)
        if gate_value.get("ledgerPhase") != "executing":
            raise RuntimeError("fault gate did not stop at the executing ledger phase")
        if gate_value.get("networkDevicePresent") is not False:
            raise RuntimeError("Entity carrier had a network device at the fault gate")
        ledger_paths = sorted((args.state_root / "run-ledgers").glob("*.json"))
        if len(ledger_paths) != 1:
            raise RuntimeError("Entity acceptance did not retain exactly one Run ledger")
        ledger_path = ledger_paths[0]
        ledger_before = ledger_path.read_bytes()
        ledger_value = _read_object(ledger_path, "pre-kill Entity ledger")
        qemu_was_alive = _identity_alive(
            ledger_value.get("qemuPid"), ledger_value.get("qemuStartTime")
        )
        swtpm_was_alive = _identity_alive(
            ledger_value.get("swtpmPid"), ledger_value.get("swtpmStartTime")
        )
        if not qemu_was_alive or not swtpm_was_alive:
            raise RuntimeError("native Entity carrier was not alive at the controller-loss gate")

        os.kill(process.pid, signal.SIGKILL)
        child_return_code = process.wait(timeout=10)
        qemu_survived = _identity_alive(
            ledger_value.get("qemuPid"), ledger_value.get("qemuStartTime")
        )
        swtpm_survived = _identity_alive(
            ledger_value.get("swtpmPid"), ledger_value.get("swtpmStartTime")
        )
        if not qemu_survived or not swtpm_survived:
            raise RuntimeError("native Entity carrier did not survive controller SIGKILL")

        destination = _destination(
            args.state_root,
            args.base_manifest,
            memory_mib=args.memory_mib,
        )
        identity = destination.execution_identity
        if identity.get("revision") != "3":
            raise RuntimeError("Entity acceptance is not using recovery identity revision 3")
        post_kill_observation = _observe_unpublished_physical_state(
            destination,
            request,
            ledger_path,
            ledger_before,
        )
        reconcile = destination.handle(_reconcile_request(request))
        ledger_after_reconcile = ledger_path.read_bytes()
        owner_after = _read_object(ledger_path, "post-reconcile Entity ledger")
        receipt_path = destination._receipt_path(MIGRATION_ID)
        qemu_preserved = _identity_alive(
            owner_after.get("qemuPid"), owner_after.get("qemuStartTime")
        )
        swtpm_preserved = _identity_alive(
            owner_after.get("swtpmPid"), owner_after.get("swtpmStartTime")
        )
        reconcile_ok = (
            post_kill_observation.get("completedButUnpublishedObservable") is True
            and reconcile.get("status") == "materialized"
            and ledger_after_reconcile != ledger_before
            and owner_after.get("phase") == "migration-running-contained"
            and owner_after.get("ownerPid") == ledger_value.get("ownerPid")
            and owner_after.get("ownerStartTime") == ledger_value.get("ownerStartTime")
            and qemu_preserved
            and swtpm_preserved
            and receipt_path.is_file()
        )
        if not reconcile_ok:
            raise RuntimeError(
                "fresh Entity reconcile did not publish the observed carrier exactly"
            )

        repeated = destination.handle(request)
        ledger_after_repeat = ledger_path.read_bytes()
        repeat_ok = repeated == reconcile and ledger_after_repeat == ledger_after_reconcile
        if not repeat_ok:
            raise RuntimeError("repeated Entity materialize changed the recovered publication")

        cleanup = _cleanup(destination, request)
        qemu_closed = not _identity_alive(
            ledger_value.get("qemuPid"), ledger_value.get("qemuStartTime")
        )
        swtpm_closed = not _identity_alive(
            ledger_value.get("swtpmPid"), ledger_value.get("swtpmStartTime")
        )
        if not cleanup.get("clean") or not qemu_closed or not swtpm_closed:
            raise RuntimeError("Entity acceptance cleanup did not close the native carrier")

        evidence: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.world-entity-controller-loss-acceptance",
            "status": "passed",
            "sourceRevision": _source_revision(),
            "migrationId": MIGRATION_ID,
            "planDigest": request["planDigest"],
            "faultPoint": "after-qmp-before-stable-publication",
            "preKill": {
                "ledgerPhase": ledger_value.get("phase"),
                "controllerOwnsLedger": (
                    ledger_value.get("ownerPid") == gate_value.get("controllerPid")
                ),
                "qemuAlive": qemu_was_alive,
                "swtpmAlive": swtpm_was_alive,
                "networkDevicePresent": gate_value.get("networkDevicePresent"),
            },
            "controllerLoss": {
                "signal": "SIGKILL",
                "childReturnCode": child_return_code,
                "qemuSurvived": qemu_survived,
                "swtpmSurvived": swtpm_survived,
            },
            "postKillObservation": post_kill_observation,
            "freshReconcile": {
                "status": reconcile.get("status"),
                "stablePublicationCreated": ledger_after_reconcile != ledger_before,
                "stablePhase": owner_after.get("phase"),
                "predecessorOwnerPreserved": (
                    owner_after.get("ownerPid") == ledger_value.get("ownerPid")
                    and owner_after.get("ownerStartTime") == ledger_value.get("ownerStartTime")
                ),
                "qemuIdentityPreserved": qemu_preserved,
                "swtpmIdentityPreserved": swtpm_preserved,
                "receiptPresent": receipt_path.is_file(),
                "physicalBodyReplay": False,
            },
            "repeatedMaterialize": {
                "sameResponse": repeated == reconcile,
                "ledgerBytesUnchanged": ledger_after_repeat == ledger_after_reconcile,
                "physicalBodyReplay": False,
            },
            "cleanup": {
                "clean": cleanup.get("clean"),
                "qemuClosed": qemu_closed,
                "swtpmClosed": swtpm_closed,
                "runDirectoryRemoved": cleanup.get("runDirectoryRemoved"),
                "ledgerRemoved": cleanup.get("ledgerRemoved"),
            },
        }
        if args.output is not None:
            _write_json(args.output, evidence)
        print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if destination is not None and cleanup is None:
            try:
                if list((args.state_root / "run-ledgers").glob("*.json")):
                    _cleanup(destination, request)
            except Exception:
                pass
        request_file.unlink(missing_ok=True)
        gate.unlink(missing_ok=True)
        if args.state_root.exists():
            shutil.rmtree(args.state_root, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Physical World Entity controller-loss acceptance")
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=768)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--request-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--gate", type=Path, help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.child:
        if args.request_file is None or args.gate is None:
            raise SystemExit("child mode requires --request-file and --gate")
        return _child(args)
    return _parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
