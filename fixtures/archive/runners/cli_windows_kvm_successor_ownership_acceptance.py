from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, validate_json
from ordivon_security.cli_windows_kvm_c1a_acceptance import _git_revision
from ordivon_security.cli_windows_kvm_c1b_acceptance import (
    _host_namespace_truth,
    _ledger_semantic_binding,
    _process_truth,
)
from ordivon_security.cli_windows_kvm_fresh_controller_continuation_acceptance import (
    _continue_peer_b_from_root_veth,
    _digest_bytes,
)
from ordivon_security.cli_windows_kvm_partial_materialization_acceptance import (
    _FAULT_POINT,
    _cleanup_root_links,
    _link_names,
    _root_link_truth,
)
from ordivon_security.cli_windows_kvm_s3_acceptance import _write_receipt
from ordivon_security.cli_windows_kvm_successor_reconciler_race_acceptance import (
    _successor_preflight,
    _wait_for_path,
    _write_private,
)
from ordivon_security.providers.windows_kvm import _load_object, _terminate_pid
from ordivon_security.range.windows_fabric_reconcile import (
    _identity_alive,
    reconcile_windows_fabric_range_runs,
)
from ordivon_security.range.windows_fabric_recovery_ownership import (
    acquire_windows_fabric_successor_claim,
)


def _claimed_successor(args: argparse.Namespace) -> None:
    ledgers = sorted((args.state_root / "run-ledgers").glob("*.json"))
    if len(ledgers) != 1:
        raise RuntimeError(f"claimed successor expected one ledger, found {len(ledgers)}")
    ledger_path = ledgers[0]
    inherited_bytes = ledger_path.read_bytes()
    ledger = _load_object(ledger_path, "claimed successor inherited ledger")
    claim = acquire_windows_fabric_successor_claim(
        args.state_root,
        ledger_path=ledger_path,
        expected_ledger_digest=_digest_bytes(inherited_bytes),
        purpose="continue-partial-peer-b",
    )
    if claim is None:
        raise RuntimeError("claimed successor lost the recovery gate before acquisition")
    try:
        preflight = _successor_preflight(args, ledger_path, ledger)
        ready: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.claimed-successor-ready",
            "claim": claim.claim,
            "preflight": preflight,
            "claimantPid": claim.claim.get("claimantPid"),
            "claimantStartTime": claim.claim.get("claimantStartTime"),
        }
        _write_private(args.successor_ready, ready)
        _wait_for_path(args.release_gate, timeout_seconds=args.race_timeout_seconds)
        result: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.claimed-successor-continuation-result",
            "status": "unknown",
            "claim": claim.claim,
            "startedAtNs": time.time_ns(),
        }
        try:
            continuation, peer_process = _continue_peer_b_from_root_veth(
                args=args,
                ledger_path=ledger_path,
                ledger=ledger,
            )
            result["status"] = "continued"
            result["continuation"] = continuation
            result["peerProcessPoll"] = peer_process.poll()
            result["finishedAtNs"] = time.time_ns()
            _write_private(args.successor_result, result)
            # Hold exact recovery authority until the supervisor intentionally kills this successor.
            while True:
                time.sleep(1)
        except BaseException as error:
            result["status"] = "failed"
            result["errorType"] = type(error).__name__
            result["errorMessage"] = str(error)
            result["finishedAtNs"] = time.time_ns()
            _write_private(args.successor_result, result)
            raise
    finally:
        # Normal error/exit releases the gate and marks metadata. SIGKILL bypasses this block;
        # the kernel still releases flock while the durable metadata remains state=held.
        claim.release(disposition="released-by-successor")


def _run_reconciler(args: argparse.Namespace, receipt: Path) -> JsonObject:
    return reconcile_windows_fabric_range_runs(args.state_root, receipt_path=receipt)


def _exact_cleanup(args: argparse.Namespace, inherited: JsonObject) -> JsonObject:
    session_id = inherited.get("rangeSessionId")
    if not isinstance(session_id, str):
        raise RuntimeError("ownership experiment cleanup lacks session identity")
    _, peer_veth, fabric_veth = _link_names(session_id)
    raw_namespaces = inherited.get("ownedNamespaceCandidates")
    namespaces = (
        cast(list[str], raw_namespaces)
        if isinstance(raw_namespaces, list)
        and all(isinstance(item, str) for item in raw_namespaces)
        else []
    )
    listed = subprocess.run(
        ["/usr/bin/ip", "netns", "list"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    present = {line.split()[0] for line in listed.stdout.splitlines() if line.strip()}
    requested_namespaces: list[str] = []
    for name in namespaces:
        if name not in present:
            continue
        requested_namespaces.append(name)
        subprocess.run(
            ["/usr/bin/ip", "netns", "del", name],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    root_cleanup = _cleanup_root_links((peer_veth, fabric_veth))
    terminated: JsonObject = {}
    for label, pid_key, start_key, fragment in (
        ("peer", "peerPid", "peerStartTime", "python"),
        ("capture", "capturePid", "captureStartTime", "tcpdump"),
        ("qemu", "qemuPid", "qemuStartTime", "qemu-system-x86_64"),
        ("swtpm", "swtpmPid", "swtpmStartTime", "swtpm"),
    ):
        pid = inherited.get(pid_key, 0)
        start = inherited.get(start_key)
        closed = True
        if isinstance(pid, int) and pid > 0:
            closed = _terminate_pid(
                pid,
                expected_fragment=fragment,
                expected_start_time=start if isinstance(start, int) else None,
            )
        terminated[label] = closed
    after = subprocess.run(
        ["/usr/bin/ip", "netns", "list"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    after_names = {line.split()[0] for line in after.stdout.splitlines() if line.strip()}
    residual_namespaces = [name for name in namespaces if name in after_names]
    payload: JsonObject = {
        "authority": "experiment-cleanup-not-recovery-law",
        "requestedNamespaces": requested_namespaces,
        "residualNamespaces": residual_namespaces,
        "rootLinks": root_cleanup,
        "terminated": terminated,
        "clean": (
            not residual_namespaces
            and root_cleanup.get("clean") is True
            and all(value is True for value in terminated.values())
        ),
    }
    validate_json(payload)
    return payload


def _supervisor(args: argparse.Namespace) -> None:
    revision = _git_revision(Path.cwd(), "Security")
    args.state_root.mkdir(parents=True, exist_ok=False)
    args.state_root.chmod(0o755)
    args.gate.parent.mkdir(parents=True, exist_ok=True)
    owner_cmd = [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_fresh_controller_continuation_acceptance",
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
        "--owner-wait-seconds",
        str(args.owner_wait_seconds),
    ]
    owner = subprocess.Popen(owner_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        owner_out, owner_err = owner.communicate(timeout=args.owner_wait_seconds + 60)
    except subprocess.TimeoutExpired as error:
        owner.kill()
        owner_out, owner_err = owner.communicate(timeout=15)
        raise TimeoutError("ownership owner did not reach partial kill gate") from error
    if owner.returncode != -signal.SIGKILL:
        raise RuntimeError(f"ownership owner did not die by SIGKILL: {owner.returncode}")

    ledgers = sorted((args.state_root / "run-ledgers").glob("*.json"))
    if len(ledgers) != 1:
        raise RuntimeError(
            f"ownership experiment expected one inherited ledger, found {len(ledgers)}"
        )
    ledger_path = ledgers[0]
    inherited_bytes = ledger_path.read_bytes()
    inherited = _load_object(ledger_path, "ownership inherited ledger")
    before_process = _process_truth(inherited)
    before_namespace = _host_namespace_truth(inherited)
    _, peer_veth, fabric_veth = _link_names(cast(str, inherited["rangeSessionId"]))
    before_root = _root_link_truth(names=(peer_veth, fabric_veth))

    successor_cmd = [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_successor_ownership_acceptance",
        "--successor",
        "--base-manifest",
        str(args.base_manifest),
        "--state-root",
        str(args.state_root),
        "--gate",
        str(args.gate),
        "--token",
        args.token,
        "--successor-ready",
        str(args.successor_ready),
        "--successor-result",
        str(args.successor_result),
        "--release-gate",
        str(args.release_gate),
        "--first-reconciler-result",
        str(args.first_reconciler_result),
        "--second-reconciler-result",
        str(args.second_reconciler_result),
        "--memory-mib",
        str(args.memory_mib),
        "--vcpus",
        str(args.vcpus),
        "--race-timeout-seconds",
        str(args.race_timeout_seconds),
    ]
    successor = subprocess.Popen(
        successor_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for_path(args.successor_ready, timeout_seconds=args.race_timeout_seconds)
    ready = _load_object(args.successor_ready, "claimed successor ready")
    claim_raw = ready.get("claim")
    if not isinstance(claim_raw, dict):
        raise RuntimeError("claimed successor ready record lacks durable claim")
    claim = cast(JsonObject, claim_raw)

    first_reconcile = _run_reconciler(args, args.first_reconciler_result)
    after_first_process = _process_truth(inherited)
    after_first_namespace = _host_namespace_truth(inherited)
    after_first_root = _root_link_truth(names=(peer_veth, fabric_veth))

    _write_private(
        args.release_gate,
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.claimed-successor-release-to-continue",
            "releasedAtNs": time.time_ns(),
        },
    )
    _wait_for_path(args.successor_result, timeout_seconds=args.race_timeout_seconds)
    successor_result = _load_object(args.successor_result, "claimed successor result")
    if successor_result.get("status") != "continued":
        successor.kill()
        successor.communicate(timeout=10)
        raise RuntimeError(f"claimed successor failed to continue: {successor_result}")
    continued_ledgers = sorted((args.state_root / "run-ledgers").glob("*.json"))
    if len(continued_ledgers) != 1:
        successor.kill()
        successor.communicate(timeout=10)
        raise RuntimeError("claimed successor lost durable ledger after continuation")
    continued = _load_object(continued_ledgers[0], "claimed successor continued ledger")
    while_claim_process = _process_truth(continued)
    while_claim_namespace = _host_namespace_truth(continued)
    while_claim_root = _root_link_truth(names=(peer_veth, fabric_veth))
    claim_path = args.state_root / "recovery-claims" / f"{ledger_path.stem}.json"
    held_claim = _load_object(claim_path, "held successor claim")

    successor_pid = ready.get("claimantPid")
    successor_start = ready.get("claimantStartTime")
    successor.kill()
    successor_out, successor_err = successor.communicate(timeout=15)
    successor_dead = not _identity_alive(successor_pid, successor_start)
    stale_claim = _load_object(claim_path, "post-SIGKILL stale successor claim")

    second_reconcile = _run_reconciler(args, args.second_reconciler_result)
    claim_removed = not claim_path.exists()
    final_ledger_count = len(list((args.state_root / "run-ledgers").glob("*.json")))
    final_process = _process_truth(continued)
    final_namespace = _host_namespace_truth(continued)
    final_root = _root_link_truth(names=(peer_veth, fabric_veth))
    cleanup = _exact_cleanup(args, continued)

    first_result = (
        first_reconcile["results"][0]
        if isinstance(first_reconcile.get("results"), list) and first_reconcile["results"]
        else {}
    )
    second_result = (
        second_reconcile["results"][0]
        if isinstance(second_reconcile.get("results"), list) and second_reconcile["results"]
        else {}
    )
    gates = {
        "ownerKilledAtPartialGate": owner.returncode == -signal.SIGKILL,
        "successorAcquiredExactGenerationClaim": claim.get("ledgerDigest")
        == _digest_bytes(inherited_bytes)
        and claim.get("state") == "held",
        "predecessorHistoryWasNotRewritten": claim.get("predecessorOwnerPid")
        == inherited.get("ownerPid")
        and inherited.get("ownerPid") != claim.get("claimantPid"),
        "firstReconcilerDeferredToLiveSuccessor": first_reconcile.get("reconciled") == 0
        and first_reconcile.get("skippedSuccessorActive") == 1
        and isinstance(first_result, dict)
        and first_result.get("decision") == "skipped-successor-active",
        "firstReconcilerDidNotMutateWorld": after_first_process.get("qemuAlive") is True
        and after_first_process.get("swtpmAlive") is True
        and set(cast(list[str], after_first_namespace.get("ownedNamespacesPresent", [])))
        == set(cast(list[str], before_namespace.get("ownedNamespacesPresent", [])))
        and after_first_root.get("presentNames") == before_root.get("presentNames"),
        "successorContinuedWhileHoldingClaim": continued.get("topologyPhase") == "peer-b-present"
        and continued.get("currentPeerAddress") == "10.253.70.4"
        and held_claim.get("state") == "held"
        and while_claim_process.get("qemuAlive") is True,
        "successorSigkillReleasedPhysicalAuthority": successor.returncode == -signal.SIGKILL
        and successor_dead,
        "durableClaimRetainedCrashProvenance": stale_claim.get("state") == "held"
        and stale_claim.get("claimId") == claim.get("claimId"),
        "secondReconcilerAcquiredAfterSuccessorDeath": second_reconcile.get("reconciled") == 1
        and second_reconcile.get("skippedSuccessorActive") == 0
        and isinstance(second_result, dict)
        and second_result.get("decision") == "reconciled",
        "secondReconcilerObservedExactStaleClaim": isinstance(second_result, dict)
        and isinstance(second_result.get("successorClaimObserved"), dict)
        and cast(dict[str, object], second_result["successorClaimObserved"]).get("claimId")
        == claim.get("claimId"),
        "claimMetadataRemovedAfterFinalClosure": claim_removed,
        "finalRecoveryClosedWorld": final_ledger_count == 0
        and final_process.get("qemuAlive") is False
        and final_process.get("swtpmAlive") is False
        and final_process.get("peerAlive") is False
        and final_process.get("captureAlive") is False
        and not cast(list[object], final_namespace.get("ownedNamespacesPresent", []))
        and not cast(list[object], final_root.get("presentNames", [])),
        "experimentCleanupFoundNoResidualWork": cleanup.get("clean") is True
        and cleanup.get("requestedNamespaces") == []
        and cast(dict[str, object], cleanup.get("rootLinks", {})).get("requested") == [],
    }
    passed = all(gates.values())
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.successor-ownership-acceptance",
        "status": "accepted" if passed else "failed",
        "securityRevision": revision,
        "faultPoint": _FAULT_POINT,
        "owner": {
            "returnCode": owner.returncode,
            "stdoutTail": owner_out[-1500:],
            "stderrTail": owner_err[-1500:],
        },
        "inheritedLedger": {
            "byteLength": len(inherited_bytes),
            "sha256": _digest_bytes(inherited_bytes),
            "semanticEffectBinding": _ledger_semantic_binding(inherited),
            "ownerPid": inherited.get("ownerPid"),
            "ownerStartTime": inherited.get("ownerStartTime"),
            "topologyPhase": inherited.get("topologyPhase"),
        },
        "beforeClaim": {
            "processTruth": before_process,
            "namespaceTruth": before_namespace,
            "rootLinkTruth": before_root,
        },
        "successorReady": ready,
        "firstReconciliation": first_reconcile,
        "afterFirstReconciliation": {
            "processTruth": after_first_process,
            "namespaceTruth": after_first_namespace,
            "rootLinkTruth": after_first_root,
        },
        "successorContinuation": successor_result,
        "whileSuccessorClaimHeld": {
            "claim": held_claim,
            "processTruth": while_claim_process,
            "namespaceTruth": while_claim_namespace,
            "rootLinkTruth": while_claim_root,
            "ledger": {
                "topologyPhase": continued.get("topologyPhase"),
                "currentPeerAddress": continued.get("currentPeerAddress"),
                "peerNamespace": continued.get("peerNamespace"),
                "peerPid": continued.get("peerPid"),
                "peerStartTime": continued.get("peerStartTime"),
            },
        },
        "successorCrash": {
            "returnCode": successor.returncode,
            "stdoutTail": successor_out[-2000:],
            "stderrTail": successor_err[-2000:],
            "claimantDead": successor_dead,
            "staleClaim": stale_claim,
        },
        "secondReconciliation": second_reconcile,
        "finalTruth": {
            "ledgerCount": final_ledger_count,
            "processTruth": final_process,
            "namespaceTruth": final_namespace,
            "rootLinkTruth": final_root,
            "claimMetadataRemoved": claim_removed,
        },
        "experimentCleanup": cleanup,
        "gates": gates,
        "interpretation": {
            "predecessorIdentityRewritten": False,
            "recoveryAuthorityMutuallyExclusive": True,
            "successorClaimRequiresWallClockLease": False,
            "successorCrashAutomaticallyReleasesKernelGate": True,
            "durableClaimIsProvenanceNotTheMutex": True,
            "genericDistributedTransactionRequired": False,
        },
    }
    _write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if not passed:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prove exact successor recovery ownership against S6 reconciliation, then kill "
            "the successor and prove recovery authority becomes available again."
        )
    )
    parser.add_argument("--successor", action="store_true")
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--token", default="successor-ownership")
    parser.add_argument("--successor-ready", type=Path, required=True)
    parser.add_argument("--successor-result", type=Path, required=True)
    parser.add_argument("--release-gate", type=Path, required=True)
    parser.add_argument("--first-reconciler-result", type=Path, required=True)
    parser.add_argument("--second-reconciler-result", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--max-runtime-seconds", type=int, default=360)
    parser.add_argument("--owner-wait-seconds", type=float, default=180.0)
    parser.add_argument("--race-timeout-seconds", type=float, default=90.0)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.successor:
        _claimed_successor(args)
        return
    if args.receipt is None:
        raise ValueError("successor ownership supervisor requires --receipt")
    _supervisor(args)


if __name__ == "__main__":
    main()
