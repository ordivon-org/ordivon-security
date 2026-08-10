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
    _bridge_truth,
    _continue_peer_b_from_root_veth,
    _digest_bytes,
    _namespace_link_names,
)
from ordivon_security.cli_windows_kvm_partial_materialization_acceptance import (
    _FAULT_POINT,
    _cleanup_root_links,
    _link_names,
    _root_link_truth,
)
from ordivon_security.cli_windows_kvm_s3_acceptance import _write_receipt
from ordivon_security.providers.windows_kvm import (
    _load_object,
    _replace_private_json,
    _terminate_pid,
)
from ordivon_security.range.windows_fabric_reconcile import (
    _root_link_kinds,
    _validated_range_ledger,
    reconcile_windows_fabric_range_runs,
)


def _wait_for_path(path: Path, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {path}")


def _write_private(path: Path, payload: JsonObject) -> None:
    validate_json(payload)
    _replace_private_json(path, payload)


def _successor_preflight(
    args: argparse.Namespace, ledger_path: Path, ledger: JsonObject
) -> JsonObject:
    validated = _validated_range_ledger(
        args.state_root, args.state_root / "runs", ledger_path, ledger
    )
    if validated is None:
        raise RuntimeError("successor baseline refuses unsafe inherited ledger")
    _, namespaces, host_links, _ = validated
    if len(namespaces) != 3 or len(host_links) != 2:
        raise RuntimeError("successor baseline expected exact S6 identities")
    fabric_ns, _, peer_b_ns = namespaces
    peer_veth, fabric_veth = host_links
    bridge = ledger.get("bridgeName")
    tap = ledger.get("tapName")
    if not isinstance(bridge, str) or not isinstance(tap, str):
        raise RuntimeError("successor baseline lacks bridge/TAP identity")
    root_kinds = _root_link_kinds(Path("/usr/bin/ip"), host_links)
    namespace_truth = _host_namespace_truth(ledger)
    bridge_truth = _bridge_truth(fabric_namespace=fabric_ns, bridge_name=bridge)
    peer_links = _namespace_link_names(peer_b_ns)
    fabric_links = _namespace_link_names(fabric_ns)
    ready = (
        ledger.get("topologyPhase") == "peer-a-removed"
        and ledger.get("currentPeerAddress") is None
        and root_kinds == {peer_veth: "veth", fabric_veth: "veth"}
        and set(cast(list[str], namespace_truth.get("ownedNamespacesPresent", [])))
        == {fabric_ns, peer_b_ns}
        and peer_veth not in peer_links
        and fabric_veth not in fabric_links
        and bridge_truth.get("portNames") == [tap]
    )
    payload: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.successor-race-preflight",
        "ready": ready,
        "observedAtNs": time.time_ns(),
        "ledgerSha256": _digest_bytes(ledger_path.read_bytes()),
        "semanticEffectBinding": _ledger_semantic_binding(ledger),
        "topologyPhase": ledger.get("topologyPhase"),
        "rootLinkKinds": root_kinds,
        "namespaceTruth": namespace_truth,
        "bridgeTruth": bridge_truth,
        "peerBNamespaceLinks": peer_links,
        "fabricNamespaceLinks": fabric_links,
    }
    validate_json(payload)
    if not ready:
        raise RuntimeError("successor baseline preflight did not establish continuable world")
    return payload


def _successor(args: argparse.Namespace) -> None:
    ledgers = sorted((args.state_root / "run-ledgers").glob("*.json"))
    if len(ledgers) != 1:
        raise RuntimeError(f"successor expected one ledger, found {len(ledgers)}")
    ledger_path = ledgers[0]
    ledger = _load_object(ledger_path, "successor-race inherited ledger")
    preflight = _successor_preflight(args, ledger_path, ledger)
    _write_private(args.successor_ready, preflight)
    _wait_for_path(args.release_gate, timeout_seconds=args.race_timeout_seconds)
    started = time.time_ns()
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.successor-race-result",
        "startedAtNs": started,
        "status": "unknown",
        "preflight": preflight,
    }
    try:
        continuation, process = _continue_peer_b_from_root_veth(
            args=args, ledger_path=ledger_path, ledger=ledger
        )
        result["status"] = "continued"
        result["continuation"] = continuation
        # Do not keep a successful peer process alive during a baseline race receipt.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        result["peerExitCodeAfterBaselineStop"] = process.returncode
    except BaseException as error:
        result["status"] = "failed"
        result["errorType"] = type(error).__name__
        result["errorMessage"] = str(error)
    result["finishedAtNs"] = time.time_ns()
    _write_private(args.successor_result, result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


def _reconciler(args: argparse.Namespace) -> None:
    result = reconcile_windows_fabric_range_runs(
        args.state_root, receipt_path=args.reconciler_result
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


def _exact_experiment_cleanup(args: argparse.Namespace, inherited: JsonObject) -> JsonObject:
    session_id = inherited.get("rangeSessionId")
    if not isinstance(session_id, str):
        raise RuntimeError("experiment cleanup lacks exact session identity")
    peer_ns, peer_veth, fabric_veth = _link_names(session_id)
    candidate_namespaces = []
    raw = inherited.get("ownedNamespaceCandidates")
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        candidate_namespaces = cast(list[str], raw)
    requested_ns = []
    listed = subprocess.run(
        ["/usr/bin/ip", "netns", "list"], capture_output=True, text=True, check=False, timeout=15
    )
    present = {line.split()[0] for line in listed.stdout.splitlines() if line.strip()}
    for name in candidate_namespaces:
        if name in present:
            requested_ns.append(name)
            subprocess.run(
                ["/usr/bin/ip", "netns", "del", name],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
    # Root links are exact deterministic S6 candidates.
    root_cleanup = _cleanup_root_links((peer_veth, fabric_veth))
    terminated = {}
    for label, pid_key, start_key, fragment in (
        ("peer", "peerPid", "peerStartTime", "python"),
        ("capture", "capturePid", "captureStartTime", "tcpdump"),
        ("qemu", "qemuPid", "qemuStartTime", "qemu-system-x86_64"),
        ("swtpm", "swtpmPid", "swtpmStartTime", "swtpm"),
    ):
        pid = inherited.get(pid_key, 0)
        start = inherited.get(start_key)
        ok = True
        if isinstance(pid, int) and pid > 0:
            ok = _terminate_pid(
                pid,
                expected_fragment=fragment,
                expected_start_time=start if isinstance(start, int) else None,
            )
        terminated[label] = ok
    after_ns = subprocess.run(
        ["/usr/bin/ip", "netns", "list"], capture_output=True, text=True, check=False, timeout=15
    )
    after_names = {line.split()[0] for line in after_ns.stdout.splitlines() if line.strip()}
    residual_ns = [name for name in candidate_namespaces if name in after_names]
    payload: JsonObject = {
        "authority": "experiment-cleanup-not-recovery-law",
        "requestedNamespaces": requested_ns,
        "residualNamespaces": residual_ns,
        "rootLinks": root_cleanup,
        "terminated": terminated,
        "peerBNamespaceCandidate": peer_ns,
        "clean": not residual_ns and root_cleanup.get("clean") is True and all(terminated.values()),
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
        raise TimeoutError("race owner did not reach kill gate") from error
    if owner.returncode != -signal.SIGKILL:
        raise RuntimeError(f"race owner did not die at injected gate: {owner.returncode}")
    ledgers = sorted((args.state_root / "run-ledgers").glob("*.json"))
    if len(ledgers) != 1:
        raise RuntimeError(f"race expected one inherited ledger, found {len(ledgers)}")
    ledger_path = ledgers[0]
    inherited_bytes = ledger_path.read_bytes()
    inherited = _load_object(ledger_path, "successor-reconciler inherited ledger")
    before_process = _process_truth(inherited)
    before_ns = _host_namespace_truth(inherited)
    _, peer_veth, fabric_veth = _link_names(cast(str, inherited["rangeSessionId"]))
    before_root = _root_link_truth(names=(peer_veth, fabric_veth))

    successor_cmd = [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_successor_reconciler_race_acceptance",
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
        "--reconciler-result",
        str(args.reconciler_result),
        "--memory-mib",
        str(args.memory_mib),
        "--vcpus",
        str(args.vcpus),
        "--race-timeout-seconds",
        str(args.race_timeout_seconds),
    ]
    successor = subprocess.Popen(
        successor_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    _wait_for_path(args.successor_ready, timeout_seconds=args.race_timeout_seconds)
    successor_preflight = _load_object(args.successor_ready, "successor race ready preflight")

    reconciler_cmd = [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_successor_reconciler_race_acceptance",
        "--reconciler",
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
        "--reconciler-result",
        str(args.reconciler_result),
        "--memory-mib",
        str(args.memory_mib),
        "--vcpus",
        str(args.vcpus),
        "--race-timeout-seconds",
        str(args.race_timeout_seconds),
    ]
    race_started_ns = time.time_ns()
    reconciler = subprocess.Popen(
        reconciler_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    _write_private(
        args.release_gate,
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.successor-race-release",
            "releasedAtNs": time.time_ns(),
        },
    )
    try:
        succ_out, succ_err = successor.communicate(timeout=args.race_timeout_seconds)
    except subprocess.TimeoutExpired:
        successor.kill()
        succ_out, succ_err = successor.communicate(timeout=10)
    try:
        rec_out, rec_err = reconciler.communicate(timeout=args.race_timeout_seconds)
    except subprocess.TimeoutExpired:
        reconciler.kill()
        rec_out, rec_err = reconciler.communicate(timeout=10)
    race_finished_ns = time.time_ns()

    successor_result = (
        _load_object(args.successor_result, "successor race result")
        if args.successor_result.exists()
        else {"status": "process-failed-before-result", "returnCode": successor.returncode}
    )
    reconcile_result = (
        _load_object(args.reconciler_result, "reconciler race result")
        if args.reconciler_result.exists()
        else {"status": "process-failed-before-result", "returnCode": reconciler.returncode}
    )
    post_ledger_paths = sorted((args.state_root / "run-ledgers").glob("*.json"))
    post_ledger = None
    if len(post_ledger_paths) == 1:
        try:
            post_ledger = _load_object(post_ledger_paths[0], "post-race ledger")
        except Exception:
            post_ledger = None
    observation_ledger = post_ledger if isinstance(post_ledger, dict) else inherited
    after_process = _process_truth(cast(JsonObject, observation_ledger))
    after_ns = _host_namespace_truth(cast(JsonObject, observation_ledger))
    after_root = _root_link_truth(names=(peer_veth, fabric_veth))
    conflict = (
        successor_preflight.get("ready") is True
        and reconcile_result.get("reconciled") == 1
        and successor_result.get("status") != "continued"
    )
    cleanup = _exact_experiment_cleanup(args, inherited)
    gates = {
        "ownerKilledAtPartialGate": owner.returncode == -signal.SIGKILL,
        "successorPreflightEstablishedContinuableWorld": successor_preflight.get("ready") is True,
        "bothContendersReleasedFromSameDeadOwnerWorld": race_started_ns > 0,
        "reconcilerAdmittedOrphanClosure": reconcile_result.get("reconciled") == 1,
        "successorLostPreviouslyValidatedWorld": successor_result.get("status") == "failed",
        "ownershipConflictObserved": conflict,
        "experimentCleanupClosedResiduals": cleanup.get("clean") is True,
    }
    status = "falsifier-observed" if all(gates.values()) else "inconclusive"
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.successor-reconciler-race-baseline",
        "status": status,
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
            "topologyPhase": inherited.get("topologyPhase"),
        },
        "beforeRace": {
            "processTruth": before_process,
            "namespaceTruth": before_ns,
            "rootLinkTruth": before_root,
        },
        "successorPreflight": successor_preflight,
        "race": {
            "startedAtNs": race_started_ns,
            "finishedAtNs": race_finished_ns,
            "successorReturnCode": successor.returncode,
            "reconcilerReturnCode": reconciler.returncode,
            "successorStdoutTail": succ_out[-2500:],
            "successorStderrTail": succ_err[-2500:],
            "reconcilerStdoutTail": rec_out[-2500:],
            "reconcilerStderrTail": rec_err[-2500:],
        },
        "successorResult": cast(JsonObject, successor_result),
        "reconciliation": cast(JsonObject, reconcile_result),
        "afterRace": {
            "processTruth": after_process,
            "namespaceTruth": after_ns,
            "rootLinkTruth": after_root,
            "ledgerCount": len(post_ledger_paths),
        },
        "experimentCleanup": cleanup,
        "gates": gates,
        "interpretation": {
            "durableSuccessorOwnershipPresent": False,
            "successorObservationWasAtomicWithMutation": False,
            "reconcilerAndSuccessorHadMutuallyExclusiveAuthority": False,
            "genericLeaseRequiredProved": False,
        },
    }
    _write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if status != "falsifier-observed":
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Race one fresh S6 successor against orphan reconciliation"
    )
    p.add_argument("--successor", action="store_true")
    p.add_argument("--reconciler", action="store_true")
    p.add_argument("--base-manifest", type=Path, required=True)
    p.add_argument("--state-root", type=Path, required=True)
    p.add_argument("--receipt", type=Path)
    p.add_argument("--gate", type=Path, required=True)
    p.add_argument("--token", default="successor-race")
    p.add_argument("--successor-ready", type=Path, required=True)
    p.add_argument("--successor-result", type=Path, required=True)
    p.add_argument("--release-gate", type=Path, required=True)
    p.add_argument("--reconciler-result", type=Path, required=True)
    p.add_argument("--memory-mib", type=int, default=4096)
    p.add_argument("--vcpus", type=int, default=2)
    p.add_argument("--max-runtime-seconds", type=int, default=360)
    p.add_argument("--owner-wait-seconds", type=float, default=180.0)
    p.add_argument("--race-timeout-seconds", type=float, default=90.0)
    return p


def main() -> None:
    args = build_parser().parse_args()
    if args.successor:
        _successor(args)
        return
    if args.reconciler:
        _reconciler(args)
        return
    if args.receipt is None:
        raise ValueError("race supervisor requires --receipt")
    _supervisor(args)


if __name__ == "__main__":
    main()
