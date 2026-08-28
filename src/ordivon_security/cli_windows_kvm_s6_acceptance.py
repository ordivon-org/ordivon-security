from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from importlib.resources import files
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.acceptance_support import write_receipt
from ordivon_security.providers.windows_kvm import WindowsKvmMachineConfig
from ordivon_security.range import RangeSession, RangeSessionSpec
from ordivon_security.range.windows_fabric import WindowsFabricRangeConfig
from ordivon_security.range.windows_topology_churn import WindowsTopologyChurnRange


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _compile_canary(output_path: Path) -> JsonObject:
    source_path = Path(
        str(
            files("ordivon_security").joinpath(
                "resources", "windows_kvm", "topology_churn_canary.c"
            )
        )
    )
    compiler = Path("/usr/bin/x86_64-w64-mingw32-gcc")
    objdump = Path("/usr/bin/x86_64-w64-mingw32-objdump")
    for path in (source_path, compiler, objdump):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"S6 canary dependency is missing or unsafe: {path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(0o700)
    subprocess.run(
        [
            str(compiler),
            "-municode",
            "-Os",
            "-s",
            "-static",
            "-Wl,--dynamicbase",
            "-Wl,--nxcompat",
            "-Wl,--no-insert-timestamp",
            "-o",
            str(output_path),
            str(source_path),
            "-lws2_32",
        ],
        check=True,
        timeout=120,
    )
    output_path.chmod(0o600)
    imports = subprocess.run(
        [str(objdump), "-p", str(output_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    ).stdout.lower()
    if "ws2_32.dll" not in imports:
        raise ValueError("S6 canary does not bind the expected Winsock import")
    compiler_version = subprocess.run(
        [str(compiler), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    ).stdout.splitlines()[0]
    result: JsonObject = {
        "canaryId": "ordivon-s6-topology-churn-canary-v1",
        "sourceDigest": _digest(source_path),
        "canaryDigest": _digest(output_path),
        "canaryByteLength": output_path.stat().st_size,
        "compilerPath": str(compiler),
        "compilerDigest": _digest(compiler),
        "compilerVersion": compiler_version,
        "declaredGuestEffects": [
            "configure-one-range-local-static-ipv4-address",
            "connect-maintained-peer-a",
            "observe-peer-a-banner",
            "wait-for-management-owned-topology-change",
            "connect-maintained-peer-b",
            "observe-peer-b-banner",
            "request-no-external-network",
        ],
    }
    result["compilationDigest"] = canonical_digest(result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run S6 physical acceptance: one Windows Guest stays alive while management "
            "replaces lightweight peer-A with peer-B inside the isolated fabric."
        )
    )
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--max-runtime-seconds", type=int, default=6 * 60)
    return parser


def _guest_claim_passes(value: object) -> bool:
    if not isinstance(value, dict) or value.get("status") != "completed":
        return False
    fixture = value.get("fixtureResult")
    if not isinstance(fixture, dict):
        return False
    return (
        fixture.get("completed") is True
        and fixture.get("configuredStaticIpv4") is True
        and fixture.get("rangeRoutePresent") is True
        and fixture.get("guestNicMac") == "52-54-00-53-35-01"
        and fixture.get("peerAConnected") is True
        and fixture.get("peerABannerMatched") is True
        and fixture.get("peerBConnected") is True
        and fixture.get("peerBBannerMatched") is True
        and fixture.get("externalNetworkRequested") is False
    )


def _topology_phases(events: list[JsonObject]) -> set[str]:
    phases: set[str] = set()
    for event in events:
        if event.get("eventType") != "world.fabric-topology-observed":
            continue
        payload = event.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("phase"), str):
            phases.add(str(payload["phase"]))
    return phases


def main() -> None:
    args = build_parser().parse_args()
    token = f"{time.time_ns():x}"
    canary_root = args.state_root / "canaries"
    canary_path = canary_root / f"ordivon-s6-topology-churn-canary-{token}.exe"
    compilation = _compile_canary(canary_path)
    session: RangeSession | None = None
    final_state: JsonObject | None = None
    destroy_receipt: JsonObject | None = None
    failure: BaseException | None = None
    try:
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
        backend = WindowsTopologyChurnRange(
            WindowsFabricRangeConfig(
                machine=machine,
                canary_path=canary_path,
                canary_digest=str(compilation["canaryDigest"]),
                max_runtime_seconds=args.max_runtime_seconds,
            )
        )
        session = RangeSession(
            backend,
            RangeSessionSpec(
                session_id=f"range-session:s6-{token}",
                revision="1",
                range_id=backend.range_id,
                actor_ids=(),
                metadata={
                    "purpose": "s6-live-topology-churn-acceptance",
                    "guestMaterialization": "windows-kvm",
                    "peerMaterialization": "sequential-linux-network-namespace-processes",
                    "externalNetwork": "structurally-unrouted",
                },
            ),
        )
        session.start()
        deadline = time.monotonic() + args.max_runtime_seconds
        while True:
            inspected = session.inspect()
            session.poll_backend()
            backend_state = inspected.get("backendState")
            if isinstance(backend_state, dict) and backend_state.get("running") is False:
                final_state = backend_state
                break
            if time.monotonic() >= deadline:
                failure = TimeoutError("S6 topology churn canary exceeded the outer bound")
                session.terminate("outer-timeout", logical_time=4)
                session.poll_backend()
                inspected = session.inspect()
                backend_state = inspected.get("backendState")
                if isinstance(backend_state, dict):
                    final_state = backend_state
                break
            time.sleep(1)
        session.poll_backend()
    except BaseException as error:
        failure = error
    finally:
        if session is not None and session.state in {"running", "terminated"}:
            try:
                destroy_receipt = session.destroy(logical_time=5)
            except BaseException as cleanup_error:
                if failure is None:
                    failure = cleanup_error
        canary_path.unlink(missing_ok=True)
        if canary_root.exists() and not any(canary_root.iterdir()):
            canary_root.rmdir()

    events = [] if session is None else [event.to_dict() for event in session.events]
    event_types = [event.get("eventType") for event in events]
    phases = _topology_phases(events)
    guest_claim = None if final_state is None else final_state.get("guestClaim")
    sensor = None if final_state is None else final_state.get("sensorObservation")
    history = None if final_state is None else final_state.get("topologyHistory")
    fabric_truth = None if final_state is None else final_state.get("fabricTruth")
    history_phases = (
        [item.get("phase") for item in history if isinstance(item, dict)]
        if isinstance(history, list)
        else []
    )
    external_acceptance = {
        "topologyChurnCompleted": final_state is not None
        and final_state.get("topologyChurnCompleted") is True,
        "replacementStarted": "fabric.peer-replacement-started" in event_types,
        "replacementCompleted": "fabric.peer-replacement-completed" in event_types,
        "peerARemovalObserved": "peer-a-removed" in phases,
        "peerBAdditionObserved": "peer-b-present" in phases,
        "topologyHistoryRetained": history_phases
        == ["peer-a-present", "peer-a-removed", "peer-b-present"],
        "currentTopologyIsPeerB": isinstance(fabric_truth, dict)
        and fabric_truth.get("phase") == "peer-b-present"
        and fabric_truth.get("currentPeerAddress") == "10.253.70.4",
        "bothChallengeFlowsObserved": isinstance(sensor, dict)
        and sensor.get("peerATrafficObserved") is True
        and sensor.get("peerBTrafficObserved") is True,
        "guestObservedBothPeers": _guest_claim_passes(guest_claim),
        "singleNetworkDevicePresent": final_state is not None
        and final_state.get("networkDevicePresent") is True,
        "residualClosureClean": destroy_receipt is not None
        and destroy_receipt.get("clean") is True,
    }
    passed = all(external_acceptance.values()) and failure is None
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.s6-topology-churn-acceptance",
        "status": "accepted" if passed else "failed",
        "compilation": compilation,
        "externalAcceptance": external_acceptance,
        "finalBackendState": final_state,
        "destroyReceipt": destroy_receipt,
        "events": events,
        "failure": None
        if failure is None
        else {"errorType": type(failure).__name__, "errorMessage": str(failure)},
    }
    write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
