from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, validate_json
from ordivon_security.acceptance_support import git_revision, write_receipt
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineConfig,
    _load_object,
    _replace_private_json,
)
from ordivon_security.range import (
    RangeAuthority,
    RangeEffectRequest,
    RangeSession,
    RangeSessionSpec,
)
from ordivon_security.range.windows_fabric import WindowsFabricRangeConfig, _run
from ordivon_security.range.windows_fabric_reconcile import (
    _identity_alive,
    reconcile_windows_fabric_range_runs,
)
from ordivon_security.range.windows_topology_churn import WindowsTopologyChurnRange
from ordivon_security.windows_kvm_acceptance_support import compile_topology_churn_canary

_ACTOR_ID = "actor:c1b-interrupted-controller"
_AUTHORITY_ID = "range-authority:c1b-interrupted-controller"
_ZONE_REF = "zone:s6-fabric"
_CAPABILITY = "fabric.peer-replacement"
_EFFECT_TYPE = "fabric.replace-peer-a-with-peer-b"
_MID_FAULT_POINT = "after-peer-a-removed-before-peer-b"
_COMPLETE_FAULT_POINT = "after-peer-b-persisted-before-completion-event"
_FAULT_POINTS = {_MID_FAULT_POINT, _COMPLETE_FAULT_POINT}


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _ledger_semantic_binding(ledger: JsonObject) -> JsonObject | None:
    raw = ledger.get("actorReplacementRequest")
    if not isinstance(raw, dict):
        return None
    return cast(JsonObject, raw)


def _host_namespace_truth(ledger: JsonObject, *, ip_path: Path = Path("/usr/bin/ip")) -> JsonObject:
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
        raise ValueError("C1-B ledger lacks deterministic namespace candidates")
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


class _InterruptedConsequenceRange(WindowsTopologyChurnRange):
    def __init__(self, *args: object, gate_path: Path, fault_point: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        if fault_point not in _FAULT_POINTS:
            raise ValueError("C1-B fault point is unsupported")
        self._c1b_gate_path = gate_path
        self._c1b_fault_point = fault_point

    def _kill_at_gate(self, run) -> None:  # type: ignore[no-untyped-def]
        ledger_path = Path(cast(str, run.state["runStatePath"]))
        ledger_bytes = ledger_path.read_bytes()
        payload: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1b-owner-loss-gate",
            "faultPoint": self._c1b_fault_point,
            "ownerPid": os.getpid(),
            "sessionId": run.instance.session_id,
            "instanceId": run.instance.instance_id,
            "topologyPhase": run.state.get("topologyPhase"),
            "currentPeerAddress": run.state.get("currentPeerAddress"),
            "actorReplacementRequest": copy.deepcopy(run.state.get("actorReplacementRequest")),
            "actorReplacementReceipt": copy.deepcopy(run.state.get("actorReplacementReceipt")),
            "ledgerSha256AtGate": _digest_bytes(ledger_bytes),
            "ledgerByteLengthAtGate": len(ledger_bytes),
        }
        validate_json(payload)
        _replace_private_json(self._c1b_gate_path, payload)
        os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError("C1-B owner survived SIGKILL injection")

    def _start_peer_b(self, run):  # type: ignore[no-untyped-def]
        if self._c1b_fault_point == _MID_FAULT_POINT:
            self._kill_at_gate(run)
        return super()._start_peer_b(run)

    def _persist_running_state(self, run) -> None:  # type: ignore[no-untyped-def]
        super()._persist_running_state(run)
        if (
            self._c1b_fault_point == _COMPLETE_FAULT_POINT
            and run.state.get("topologyPhase") == "peer-b-present"
            and run.state.get("actorReplacementRequest") is not None
        ):
            self._kill_at_gate(run)


def _machine_config(args: argparse.Namespace) -> WindowsKvmMachineConfig:
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


def _owner(args: argparse.Namespace) -> None:
    token = args.token
    canary_root = args.state_root / "canaries"
    canary_path = canary_root / f"ordivon-c1b-interrupted-{token}.exe"
    compilation = compile_topology_churn_canary(canary_path)
    authority = RangeAuthority(
        authority_id=_AUTHORITY_ID,
        revision="1",
        actor_id=_ACTOR_ID,
        zone_refs=(_ZONE_REF,),
        capabilities=(_CAPABILITY,),
        external_boundary="denied",
        metadata={"purpose": "c1b-interrupted-consequence"},
    )
    backend = _InterruptedConsequenceRange(
        WindowsFabricRangeConfig(
            machine=_machine_config(args),
            canary_path=canary_path,
            canary_digest=str(compilation["canaryDigest"]),
            max_runtime_seconds=args.max_runtime_seconds,
        ),
        replacement_trigger="actor-authorized",
        gate_path=args.gate,
        fault_point=args.fault_point,
    )
    session = RangeSession(
        backend,
        RangeSessionSpec(
            session_id=f"range-session:c1b-{token}",
            revision="1",
            range_id=backend.range_id,
            actor_ids=(_ACTOR_ID,),
            authorities=(authority,),
            metadata={
                "purpose": "c1b-interrupted-consequence-baseline",
                "faultPoint": args.fault_point,
                "externalNetwork": "structurally-unrouted",
            },
        ),
    )
    session.start()
    session.update_actor_presence(_ACTOR_ID, "active", logical_time=1)
    request = RangeEffectRequest(
        request_id=f"range-effect-request:c1b-{token}",
        actor_id=_ACTOR_ID,
        authority_id=_AUTHORITY_ID,
        zone_ref=_ZONE_REF,
        capability=_CAPABILITY,
        effect_type=_EFFECT_TYPE,
        payload={"source": "c1b-deterministic-recovery-probe"},
    )
    admission = session.admit_effect(request, logical_time=2)
    if not admission.admitted:
        raise RuntimeError(f"C1-B deterministic request was rejected: {admission.reason}")
    receipt = backend.request_peer_replacement(session.instance, admission)
    if receipt.get("worldEffectVerified") is not False:
        raise RuntimeError("C1-B backend receipt unexpectedly claims world truth")

    run = backend._run_for(session.instance)
    peer_namespace = cast(str, run.state["peerNamespace"])
    probe = (
        "import socket; "
        "s=socket.socket(); s.settimeout(10); "
        f"s.connect(('10.253.70.3',{backend.peer_port})); "
        "s.recv(128); s.close()"
    )
    _run(
        [
            str(backend.config.ip_path),
            "netns",
            "exec",
            peer_namespace,
            str(backend.config.python_path),
            "-c",
            probe,
        ],
        timeout=20,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        time.sleep(0.25)
    raise TimeoutError("C1-B owner never reached the injected kill gate")


def _process_truth(ledger: JsonObject) -> JsonObject:
    truth: JsonObject = {
        "ownerAlive": _identity_alive(ledger.get("ownerPid"), ledger.get("ownerStartTime")),
        "qemuAlive": _identity_alive(ledger.get("qemuPid"), ledger.get("qemuStartTime")),
        "swtpmAlive": _identity_alive(ledger.get("swtpmPid"), ledger.get("swtpmStartTime")),
        "captureAlive": _identity_alive(ledger.get("capturePid"), ledger.get("captureStartTime")),
        "peerAlive": _identity_alive(ledger.get("peerPid"), ledger.get("peerStartTime")),
    }
    validate_json(truth)
    return truth


def _supervisor(args: argparse.Namespace) -> None:
    security_revision = git_revision(Path.cwd(), "Security")
    token = args.token
    args.state_root.mkdir(parents=True, exist_ok=False)
    args.state_root.chmod(0o755)
    args.gate.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_c1b_acceptance",
        "--owner",
        "--base-manifest",
        str(args.base_manifest),
        "--state-root",
        str(args.state_root),
        "--gate",
        str(args.gate),
        "--token",
        token,
        "--fault-point",
        args.fault_point,
        "--memory-mib",
        str(args.memory_mib),
        "--vcpus",
        str(args.vcpus),
        "--max-runtime-seconds",
        str(args.max_runtime_seconds),
    ]
    started = time.monotonic()
    owner = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = owner.communicate(timeout=args.supervisor_timeout_seconds)
    except subprocess.TimeoutExpired as error:
        owner.kill()
        stdout, stderr = owner.communicate(timeout=15)
        raise TimeoutError("C1-B owner did not reach injected SIGKILL bound") from error
    elapsed_ms = int((time.monotonic() - started) * 1000)

    ledgers = sorted((args.state_root / "run-ledgers").glob("*.json"))
    if len(ledgers) != 1:
        raise RuntimeError(f"C1-B expected one surviving ledger, found {len(ledgers)}")
    ledger_path = ledgers[0]
    ledger_bytes = ledger_path.read_bytes()
    ledger = _load_object(ledger_path, "C1-B interrupted Range ledger")
    gate = _load_object(args.gate, "C1-B owner-loss gate")
    host_truth = _host_namespace_truth(ledger)
    process_truth = _process_truth(ledger)
    binding = _ledger_semantic_binding(ledger)
    ledger_receipt = ledger.get("actorReplacementReceipt")
    gate_binding = gate.get("actorReplacementRequest")
    gate_receipt = gate.get("actorReplacementReceipt")

    pre_reconcile: JsonObject = {
        "ownerReturnCode": owner.returncode,
        "ownerElapsedMs": elapsed_ms,
        "ownerStdoutTail": stdout[-2000:],
        "ownerStderrTail": stderr[-2000:],
        "gate": gate,
        "ledgerSha256": _digest_bytes(ledger_bytes),
        "ledgerByteLength": len(ledger_bytes),
        "ledger": ledger,
        "ledgerSemanticBinding": binding,
        "ledgerSemanticReceipt": ledger_receipt,
        "hostTruth": host_truth,
        "processTruth": process_truth,
    }
    validate_json(pre_reconcile)

    reconciliation_path = args.state_root / "receipts" / f"c1b-reconcile-{token}.json"
    reconciliation = reconcile_windows_fabric_range_runs(
        args.state_root,
        receipt_path=reconciliation_path,
    )
    post_namespaces = _host_namespace_truth(
        {
            "ownedNamespaceCandidates": ledger.get("ownedNamespaceCandidates"),
            "fabricNamespace": ledger.get("fabricNamespace"),
            "bridgeName": ledger.get("bridgeName"),
        }
    )

    common_gates = {
        "ownerKilledAtExactInjectedGate": owner.returncode == -signal.SIGKILL
        and gate.get("faultPoint") == args.fault_point,
        "inMemoryEffectBindingExistedBeforeKill": isinstance(gate_binding, dict)
        and gate_binding.get("effectId") is not None
        and gate_binding.get("requestDigest") is not None
        and gate_binding.get("admissionDigest") is not None,
        "ledgerReachedExpectedPhysicalPhase": (
            args.fault_point == _MID_FAULT_POINT
            and ledger.get("topologyPhase") == "peer-a-removed"
            and ledger.get("currentPeerAddress") is None
        )
        or (
            args.fault_point == _COMPLETE_FAULT_POINT
            and ledger.get("topologyPhase") == "peer-b-present"
            and ledger.get("currentPeerAddress") == "10.253.70.4"
        ),
        "hostObservedExpectedPhysicalWorld": host_truth.get("fabricNamespacePresent") is True
        and (
            (
                args.fault_point == _MID_FAULT_POINT
                and len(cast(list[object], host_truth.get("ownedNamespacesPresent", []))) == 1
                and len(cast(list[object], host_truth.get("bridgePorts", []))) == 1
            )
            or (
                args.fault_point == _COMPLETE_FAULT_POINT
                and len(cast(list[object], host_truth.get("ownedNamespacesPresent", []))) == 2
                and len(cast(list[object], host_truth.get("bridgePorts", []))) == 2
            )
        ),
        "ownerDeadChildrenStillRecoverable": process_truth.get("ownerAlive") is False
        and process_truth.get("qemuAlive") is True
        and process_truth.get("swtpmAlive") is True
        and process_truth.get("captureAlive") is True,
        "existingReconcilerClosedToZero": reconciliation.get("status") == "passed"
        and reconciliation.get("reconciled") == 1
        and reconciliation.get("attentionRequired") == 0,
        "postReconcileNamespacesAbsent": not cast(
            list[object], post_namespaces.get("ownedNamespacesPresent", [])
        ),
        "ledgerRemovedAfterReconcile": not ledger_path.exists(),
    }
    if args.expect_durable_binding:
        semantic_gates = {
            "durableLedgerPreservedSemanticEffectBinding": isinstance(binding, dict)
            and binding == gate_binding,
            "durableLedgerPreservedNonTruthReceipt": isinstance(ledger_receipt, dict)
            and ledger_receipt == gate_receipt
            and ledger_receipt.get("worldEffectVerified") is False,
            "interruptedEffectIdentityReconstructed": isinstance(binding, dict)
            and binding.get("actorId") == _ACTOR_ID
            and binding.get("authorityId") == _AUTHORITY_ID
            and binding.get("zoneRef") == _ZONE_REF
            and binding.get("capability") == _CAPABILITY
            and binding.get("effectType") == _EFFECT_TYPE
            and binding.get("effectId") is not None
            and binding.get("requestDigest") is not None
            and binding.get("admissionDigest") is not None,
        }
        status = "accepted" if all({**common_gates, **semantic_gates}.values()) else "failed"
    else:
        semantic_gates = {"durableLedgerLostSemanticEffectBinding": binding is None}
        status = (
            "falsifier-observed" if all({**common_gates, **semantic_gates}.values()) else "failed"
        )
    gates = {**common_gates, **semantic_gates}
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": (
            "ordivon.security.c1b-interrupted-consequence-acceptance"
            if args.expect_durable_binding
            else "ordivon.security.c1b-interrupted-consequence-baseline"
        ),
        "status": status,
        "securityRevision": security_revision,
        "faultPoint": args.fault_point,
        "expectedEffect": {
            "actorId": _ACTOR_ID,
            "authorityId": _AUTHORITY_ID,
            "zoneRef": _ZONE_REF,
            "capability": _CAPABILITY,
            "effectType": _EFFECT_TYPE,
        },
        "preReconcile": pre_reconcile,
        "gates": gates,
        "reconciliation": reconciliation,
        "postReconcileHostTruth": post_namespaces,
        "interpretation": {
            "physicalRecoveryAvailable": True,
            "semanticEffectReconstructionAvailable": binding is not None,
            "interruptedWorldState": (
                "peer-a-removed-before-peer-b"
                if args.fault_point == _MID_FAULT_POINT
                else "peer-b-present-before-completion-event"
            ),
            "wholeEffectReplayJustified": False,
            "physicalEffectAlreadyMaterialized": args.fault_point == _COMPLETE_FAULT_POINT,
            "automaticSuffixContinuationProved": False,
        },
    }
    write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    expected_status = "accepted" if args.expect_durable_binding else "falsifier-observed"
    if status != expected_status:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run C1-B interrupted consequence baseline")
    parser.add_argument("--owner", action="store_true")
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--token", default="c1b")
    parser.add_argument("--fault-point", choices=sorted(_FAULT_POINTS), default=_MID_FAULT_POINT)
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--max-runtime-seconds", type=int, default=360)
    parser.add_argument("--supervisor-timeout-seconds", type=float, default=150.0)
    parser.add_argument("--expect-durable-binding", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.owner:
        _owner(args)
        return
    if args.receipt is None:
        raise ValueError("C1-B supervisor requires --receipt")
    _supervisor(args)


if __name__ == "__main__":
    main()
