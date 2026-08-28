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
from ordivon_security.cli_windows_kvm_c1b_acceptance import (
    _digest_bytes,
    _host_namespace_truth,
    _ledger_semantic_binding,
    _machine_config,
    _process_truth,
)
from ordivon_security.providers.windows_kvm import _load_object, _replace_private_json
from ordivon_security.range import (
    RangeAuthority,
    RangeEffectRequest,
    RangeSession,
    RangeSessionSpec,
)
from ordivon_security.range.windows_fabric import WindowsFabricRangeConfig, _run
from ordivon_security.range.windows_fabric_reconcile import reconcile_windows_fabric_range_runs
from ordivon_security.range.windows_topology_churn import WindowsTopologyChurnRange
from ordivon_security.windows_kvm_acceptance_support import compile_topology_churn_canary

_ACTOR_ID = "actor:partial-materialization-controller"
_AUTHORITY_ID = "range-authority:partial-materialization-controller"
_ZONE_REF = "zone:s6-fabric"
_CAPABILITY = "fabric.peer-replacement"
_EFFECT_TYPE = "fabric.replace-peer-a-with-peer-b"
_FAULT_POINT = "after-peer-b-root-veth-created-before-placement"


def _link_names(session_id: str) -> tuple[str, str, str]:
    suffix = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
    return f"s6q{suffix}", f"q{suffix}", f"w{suffix}"


def _root_link_truth(*, names: tuple[str, ...], ip_path: Path = Path("/usr/bin/ip")) -> JsonObject:
    completed = subprocess.run(
        [str(ip_path), "-j", "link", "show"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    data = json.loads(completed.stdout or "[]")
    present: list[JsonObject] = []
    for item in data:
        if not isinstance(item, dict) or item.get("ifname") not in names:
            continue
        present.append(
            cast(
                JsonObject,
                {
                    "ifname": item.get("ifname"),
                    "ifindex": item.get("ifindex"),
                    "linkIndex": item.get("link_index"),
                    "linkType": item.get("link_type"),
                    "flags": item.get("flags", []),
                },
            )
        )
    truth: JsonObject = {
        "authority": "host-linux-root-netlink-observation",
        "candidateNames": list(names),
        "present": present,
        "presentNames": sorted(str(item["ifname"]) for item in present),
    }
    validate_json(truth)
    return truth


def _cleanup_root_links(
    names: tuple[str, ...], *, ip_path: Path = Path("/usr/bin/ip")
) -> JsonObject:
    before = _root_link_truth(names=names, ip_path=ip_path)
    requested: list[str] = []
    for name in names:
        current = _root_link_truth(names=names, ip_path=ip_path)
        if name not in cast(list[str], current["presentNames"]):
            continue
        requested.append(name)
        subprocess.run(
            [str(ip_path), "link", "del", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    after = _root_link_truth(names=names, ip_path=ip_path)
    receipt: JsonObject = {
        "authority": "experiment-cleanup-not-range-reconciler",
        "requested": requested,
        "before": before,
        "after": after,
        "clean": not cast(list[object], after["presentNames"]),
    }
    validate_json(receipt)
    return receipt


class _KillAfterRootVethRange(WindowsTopologyChurnRange):
    def __init__(self, *args: object, gate_path: Path, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._partial_gate_path = gate_path

    def _start_peer_b(self, run):  # type: ignore[no-untyped-def]
        peer_ns, peer_veth, fabric_veth = _link_names(run.instance.session_id)
        _run([str(self.config.ip_path), "netns", "add", peer_ns])
        for key in ("all", "default"):
            _run(
                [
                    str(self.config.ip_path),
                    "netns",
                    "exec",
                    peer_ns,
                    str(self.config.sysctl_path),
                    "-q",
                    "-w",
                    f"net.ipv6.conf.{key}.disable_ipv6=1",
                ]
            )
        _run(
            [
                str(self.config.ip_path),
                "link",
                "add",
                peer_veth,
                "type",
                "veth",
                "peer",
                "name",
                fabric_veth,
            ]
        )
        ledger_path = Path(cast(str, run.state["runStatePath"]))
        ledger_bytes = ledger_path.read_bytes()
        payload: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.partial-materialization-owner-loss-gate",
            "faultPoint": _FAULT_POINT,
            "ownerPid": os.getpid(),
            "sessionId": run.instance.session_id,
            "instanceId": run.instance.instance_id,
            "topologyPhase": run.state.get("topologyPhase"),
            "currentPeerAddress": run.state.get("currentPeerAddress"),
            "expectedPeerNamespace": peer_ns,
            "expectedRootLinks": [peer_veth, fabric_veth],
            "actorReplacementRequest": copy.deepcopy(run.state.get("actorReplacementRequest")),
            "actorReplacementReceipt": copy.deepcopy(run.state.get("actorReplacementReceipt")),
            "ledgerSha256AtGate": _digest_bytes(ledger_bytes),
            "ledgerByteLengthAtGate": len(ledger_bytes),
        }
        validate_json(payload)
        _replace_private_json(self._partial_gate_path, payload)
        os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError("partial-materialization owner survived SIGKILL injection")


def _owner(args: argparse.Namespace) -> None:
    token = args.token
    canary_root = args.state_root / "canaries"
    canary_path = canary_root / f"ordivon-partial-materialization-{token}.exe"
    compilation = compile_topology_churn_canary(canary_path)
    authority = RangeAuthority(
        authority_id=_AUTHORITY_ID,
        revision="1",
        actor_id=_ACTOR_ID,
        zone_refs=(_ZONE_REF,),
        capabilities=(_CAPABILITY,),
        external_boundary="denied",
        metadata={"purpose": "partial-materialization-recovery"},
    )
    backend = _KillAfterRootVethRange(
        WindowsFabricRangeConfig(
            machine=_machine_config(args),
            canary_path=canary_path,
            canary_digest=str(compilation["canaryDigest"]),
            max_runtime_seconds=args.max_runtime_seconds,
        ),
        replacement_trigger="actor-authorized",
        gate_path=args.gate,
    )
    session = RangeSession(
        backend,
        RangeSessionSpec(
            session_id=f"range-session:partial-{token}",
            revision="1",
            range_id=backend.range_id,
            actor_ids=(_ACTOR_ID,),
            authorities=(authority,),
            metadata={
                "purpose": "partial-materialization-recovery-baseline",
                "faultPoint": _FAULT_POINT,
                "externalNetwork": "structurally-unrouted",
            },
        ),
    )
    session.start()
    session.update_actor_presence(_ACTOR_ID, "active", logical_time=1)
    request = RangeEffectRequest(
        request_id=f"range-effect-request:partial-{token}",
        actor_id=_ACTOR_ID,
        authority_id=_AUTHORITY_ID,
        zone_ref=_ZONE_REF,
        capability=_CAPABILITY,
        effect_type=_EFFECT_TYPE,
        payload={"source": "partial-materialization-recovery-probe"},
    )
    admission = session.admit_effect(request, logical_time=2)
    if not admission.admitted:
        raise RuntimeError(f"partial-materialization request rejected: {admission.reason}")
    receipt = backend.request_peer_replacement(session.instance, admission)
    if receipt.get("worldEffectVerified") is not False:
        raise RuntimeError("backend receipt unexpectedly claims world truth")

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
    time.sleep(30)
    raise TimeoutError("partial-materialization owner never reached kill gate")


def _supervisor(args: argparse.Namespace) -> None:
    security_revision = git_revision(Path.cwd(), "Security")
    args.state_root.mkdir(parents=True, exist_ok=False)
    args.state_root.chmod(0o755)
    args.gate.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_partial_materialization_acceptance",
        "--owner",
        "--base-manifest",
        str(args.base_manifest),
        "--state-root",
        str(args.state_root),
        "--gate",
        str(args.gate),
        "--token",
        args.token,
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
        raise TimeoutError("partial-materialization owner did not reach SIGKILL gate") from error
    elapsed_ms = int((time.monotonic() - started) * 1000)

    ledgers = sorted((args.state_root / "run-ledgers").glob("*.json"))
    if len(ledgers) != 1:
        raise RuntimeError(f"expected one surviving ledger, found {len(ledgers)}")
    ledger_path = ledgers[0]
    ledger = _load_object(ledger_path, "partial-materialization Range ledger")
    gate = _load_object(args.gate, "partial-materialization kill gate")
    binding = _ledger_semantic_binding(ledger)
    process_truth = _process_truth(ledger)
    namespace_truth = _host_namespace_truth(ledger)
    expected_root_links_raw = gate.get("expectedRootLinks")
    if not isinstance(expected_root_links_raw, list) or not all(
        isinstance(item, str) for item in expected_root_links_raw
    ):
        raise ValueError("kill gate lacks expected root links")
    expected_root_links = tuple(cast(list[str], expected_root_links_raw))
    pre_root_links = _root_link_truth(names=expected_root_links)

    reconciliation_path = args.state_root / "receipts" / f"partial-reconcile-{args.token}.json"
    reconciliation = reconcile_windows_fabric_range_runs(
        args.state_root,
        receipt_path=reconciliation_path,
    )
    post_namespace_truth = _host_namespace_truth(
        {
            "ownedNamespaceCandidates": ledger.get("ownedNamespaceCandidates"),
            "fabricNamespace": ledger.get("fabricNamespace"),
            "bridgeName": ledger.get("bridgeName"),
        }
    )
    post_root_links = _root_link_truth(names=expected_root_links)
    false_clean = (
        reconciliation.get("status") == "passed"
        and reconciliation.get("reconciled") == 1
        and bool(cast(list[object], post_root_links["presentNames"]))
    )
    experiment_cleanup = _cleanup_root_links(expected_root_links)
    results = reconciliation.get("results")
    reconciled_item = (
        results[0]
        if isinstance(results, list) and len(results) == 1 and isinstance(results[0], dict)
        else {}
    )

    common_gates = {
        "ownerKilledAtPartialMaterializationGate": owner.returncode == -signal.SIGKILL
        and gate.get("faultPoint") == _FAULT_POINT,
        "effectIdentitySurvivedOwnerLoss": isinstance(binding, dict)
        and binding.get("effectId") is not None
        and binding.get("requestDigest") is not None
        and binding.get("admissionDigest") is not None,
        "stableLedgerPhaseStillSaysPeerARemoved": ledger.get("topologyPhase") == "peer-a-removed"
        and ledger.get("currentPeerAddress") is None,
        "hostObservedPeerBNamespaceCandidate": gate.get("expectedPeerNamespace")
        in cast(list[str], namespace_truth.get("ownedNamespacesPresent", [])),
        "hostObservedBothPartialRootVethEnds": set(cast(list[str], pre_root_links["presentNames"]))
        == set(expected_root_links),
        "ownerDeadWhilePhysicalSubstrateStillLive": process_truth.get("ownerAlive") is False
        and process_truth.get("qemuAlive") is True
        and process_truth.get("swtpmAlive") is True
        and process_truth.get("captureAlive") is True,
        "reconcilerReportedPassed": reconciliation.get("status") == "passed"
        and reconciliation.get("reconciled") == 1
        and reconciliation.get("attentionRequired") == 0,
        "reconcilerRemovedNamespaces": not cast(
            list[object], post_namespace_truth.get("ownedNamespacesPresent", [])
        ),
    }
    if args.expect_fixed_reconciler:
        mode_gates = {
            "reconcilerRemovedPartialRootVeth": not cast(
                list[object], post_root_links["presentNames"]
            ),
            "reconcilerReceiptOwnsHostLinkClosure": set(
                cast(list[str], reconciled_item.get("requestedHostLinks", []))
            )
            == set(expected_root_links)
            and reconciled_item.get("residualHostLinks") == [],
            "experimentCleanupFoundNoResidualWork": experiment_cleanup.get("clean") is True
            and experiment_cleanup.get("requested") == [],
        }
        status = "accepted" if all({**common_gates, **mode_gates}.values()) else "failed"
    else:
        mode_gates = {
            "existingReconcilerLeftRootVethResidual": bool(
                cast(list[object], post_root_links["presentNames"])
            ),
            "existingCleanClaimWasFalse": false_clean,
            "experimentCleanupRemovedExactResidualLinks": experiment_cleanup.get("clean") is True,
        }
        status = "falsifier-observed" if all({**common_gates, **mode_gates}.values()) else "failed"
    gates = {**common_gates, **mode_gates}
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": (
            "ordivon.security.partial-materialization-recovery-acceptance"
            if args.expect_fixed_reconciler
            else "ordivon.security.partial-materialization-recovery-baseline"
        ),
        "status": status,
        "securityRevision": security_revision,
        "faultPoint": _FAULT_POINT,
        "owner": {
            "returnCode": owner.returncode,
            "elapsedMs": elapsed_ms,
            "stdoutTail": stdout[-2000:],
            "stderrTail": stderr[-2000:],
        },
        "gate": gate,
        "ledger": ledger,
        "semanticEffectBinding": binding,
        "preReconcile": {
            "processTruth": process_truth,
            "namespaceTruth": namespace_truth,
            "rootLinkTruth": pre_root_links,
        },
        "reconciliation": reconciliation,
        "postReconcile": {
            "namespaceTruth": post_namespace_truth,
            "rootLinkTruth": post_root_links,
        },
        "experimentCleanup": experiment_cleanup,
        "gates": gates,
        "interpretation": {
            "partialMaterializationObserved": True,
            "stableTopologyPhaseSufficient": False,
            "reconcilerCleanClaimReliable": args.expect_fixed_reconciler and not false_clean,
            "automaticContinuationProved": False,
        },
    }
    write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    expected_status = "accepted" if args.expect_fixed_reconciler else "falsifier-observed"
    if status != expected_status:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Interrupt S6 peer-B after root veth creation to test partial materialization recovery"
        )
    )
    parser.add_argument("--owner", action="store_true")
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--token", default="partial")
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--max-runtime-seconds", type=int, default=360)
    parser.add_argument("--supervisor-timeout-seconds", type=float, default=150.0)
    parser.add_argument("--expect-fixed-reconciler", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.owner:
        _owner(args)
        return
    if args.receipt is None:
        raise ValueError("partial-materialization supervisor requires --receipt")
    _supervisor(args)


if __name__ == "__main__":
    main()
