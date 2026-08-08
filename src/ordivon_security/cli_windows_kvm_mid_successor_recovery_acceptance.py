from __future__ import annotations

import argparse
import json
import os
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
    _PEER_B_ADDRESS,
    _PEER_B_BANNER,
    _PEER_PORT,
    _PREFIX_LENGTH,
    _bridge_truth,
    _digest_bytes,
    _extract_guest_claim,
    _namespace_addresses,
    _namespace_link_names,
    _peer_route_truth,
    _persist_continued_ledger,
    _sensor_truth,
    _wait_identity_gone,
)
from ordivon_security.cli_windows_kvm_multiple_successors_acceptance import _one_ledger
from ordivon_security.cli_windows_kvm_partial_materialization_acceptance import (
    _FAULT_POINT,
    _link_names,
    _root_link_truth,
)
from ordivon_security.cli_windows_kvm_s3_acceptance import _write_receipt
from ordivon_security.cli_windows_kvm_s6_acceptance import _guest_claim_passes
from ordivon_security.cli_windows_kvm_successor_ownership_acceptance import _exact_cleanup
from ordivon_security.cli_windows_kvm_successor_reconciler_race_acceptance import (
    _successor_preflight,
    _wait_for_path,
    _write_private,
)
from ordivon_security.providers.windows_kvm import _load_object, _process_start_time
from ordivon_security.range.windows_fabric import _run
from ordivon_security.range.windows_fabric_reconcile import (
    _identity_alive,
    _validated_range_ledger,
    reconcile_windows_fabric_range_runs,
)
from ordivon_security.range.windows_fabric_recovery_ownership import (
    acquire_windows_fabric_successor_claim,
    read_windows_fabric_recovery_claim_history,
)

_MID_FAULT = "after-successor-veth-placement-and-bridge-before-link-up"


def _mid_world_truth(ledger: JsonObject) -> JsonObject:
    session_id = ledger.get("rangeSessionId")
    if not isinstance(session_id, str):
        raise RuntimeError("mid-successor recovery lacks rangeSessionId")
    peer_ns, peer_veth, fabric_veth = _link_names(session_id)
    fabric_ns = ledger.get("fabricNamespace")
    bridge_name = ledger.get("bridgeName")
    tap_name = ledger.get("tapName")
    if not all(isinstance(value, str) for value in (fabric_ns, bridge_name, tap_name)):
        raise RuntimeError("mid-successor recovery lacks durable fabric identity")
    process_truth = _process_truth(ledger)
    namespace_truth = _host_namespace_truth(ledger)
    peer_links = _namespace_link_names(peer_ns)
    fabric_links = _namespace_link_names(cast(str, fabric_ns))
    bridge = _bridge_truth(
        fabric_namespace=cast(str, fabric_ns),
        bridge_name=cast(str, bridge_name),
    )
    addresses = _namespace_addresses(peer_ns, peer_veth)
    routes = _peer_route_truth(peer_ns)
    root = _root_link_truth(names=(peer_veth, fabric_veth))
    exact_midpoint = (
        ledger.get("topologyPhase") == "peer-a-removed"
        and ledger.get("currentPeerAddress") is None
        and process_truth.get("qemuAlive") is True
        and process_truth.get("swtpmAlive") is True
        and process_truth.get("captureAlive") is True
        and set(cast(list[str], namespace_truth.get("ownedNamespacesPresent", [])))
        == {cast(str, fabric_ns), peer_ns}
        and peer_veth in peer_links
        and fabric_veth in fabric_links
        and set(cast(list[str], bridge.get("portNames", []))) == {cast(str, tap_name), fabric_veth}
        and f"{_PEER_B_ADDRESS}/{_PREFIX_LENGTH}" not in addresses
        and routes.get("defaultRouteAbsent") is True
        and root.get("presentNames") == []
    )
    truth: JsonObject = {
        "authority": "host-observed-mid-successor-partial-world",
        "exactMidpoint": exact_midpoint,
        "topologyPhase": ledger.get("topologyPhase"),
        "currentPeerAddress": ledger.get("currentPeerAddress"),
        "processTruth": process_truth,
        "namespaceTruth": namespace_truth,
        "peerNamespaceLinks": peer_links,
        "fabricNamespaceLinks": fabric_links,
        "bridgeTruth": bridge,
        "peerAddresses": addresses,
        "peerRoutes": routes,
        "rootLinkTruth": root,
    }
    validate_json(truth)
    return truth


def _first_successor(args: argparse.Namespace) -> None:
    ledger_path, ledger, ledger_bytes = _one_ledger(args.state_root, "first successor")
    digest = _digest_bytes(ledger_bytes)
    claim = acquire_windows_fabric_successor_claim(
        args.state_root,
        ledger_path=ledger_path,
        expected_ledger_digest=digest,
        purpose="mid-successor-first",
    )
    if claim is None:
        raise RuntimeError("first successor failed to acquire recovery authority")
    try:
        preflight = _successor_preflight(args, ledger_path, ledger)
        ready: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.mid-successor-first-ready",
            "claim": claim.claim,
            "ledgerDigest": digest,
            "preflight": preflight,
            "recordedAtNs": time.time_ns(),
        }
        _write_private(args.first_ready, ready)
        _wait_for_path(args.first_continue_gate, timeout_seconds=args.stage_timeout_seconds)

        validated = _validated_range_ledger(
            args.state_root,
            args.state_root / "runs",
            ledger_path,
            ledger,
        )
        if validated is None:
            raise RuntimeError("first successor refuses unsafe inherited ledger")
        _, namespaces, host_links, _ = validated
        if len(namespaces) != 3 or len(host_links) != 2:
            raise RuntimeError("first successor expected exact S6 resource identities")
        fabric_ns, _, peer_ns = namespaces
        peer_veth, fabric_veth = host_links
        bridge_name = ledger.get("bridgeName")
        if not isinstance(bridge_name, str):
            raise RuntimeError("first successor lacks durable bridge identity")

        _run(["/usr/bin/ip", "link", "set", peer_veth, "netns", peer_ns])
        _run(["/usr/bin/ip", "link", "set", fabric_veth, "netns", fabric_ns])
        _run(
            [
                "/usr/bin/ip",
                "-n",
                fabric_ns,
                "link",
                "set",
                fabric_veth,
                "master",
                bridge_name,
            ]
        )
        midpoint = _mid_world_truth(ledger)
        gate: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.mid-successor-kill-gate",
            "faultPoint": _MID_FAULT,
            "claim": claim.claim,
            "ledgerDigestBeforeMutation": digest,
            "ledgerDigestAtKill": _digest_bytes(ledger_path.read_bytes()),
            "worldTruth": midpoint,
            "ownerPid": os.getpid(),
            "recordedAtNs": time.time_ns(),
        }
        _write_private(args.midpoint_gate, gate)
        os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError("first successor survived SIGKILL injection")
    finally:
        claim.release(disposition="released-by-first-successor")


def _start_peer_b_service(run_path: Path, peer_ns: str) -> subprocess.Popen[bytes]:
    stdout_path = run_path / "peer-b.stdout.log"
    stderr_path = run_path / "peer-b.stderr.log"
    if stdout_path.exists() or stderr_path.exists():
        raise RuntimeError("second successor refuses pre-existing peer-B service logs")
    stdout_handle = stdout_path.open("xb")
    stderr_handle = stderr_path.open("xb")
    script = (
        "import socket; "
        "s=socket.socket(); s.settimeout(300); "
        f"s.bind(('{_PEER_B_ADDRESS}',{_PEER_PORT})); "
        "s.listen(1); c,a=s.accept(); "
        f"c.sendall({(_PEER_B_BANNER + chr(10)).encode()!r}); c.close(); s.close()"
    )
    process = subprocess.Popen(
        [
            "/usr/bin/ip",
            "netns",
            "exec",
            peer_ns,
            "/usr/bin/setpriv",
            "--reuid",
            "qemu",
            "--regid",
            "qemu",
            "--init-groups",
            "--",
            "/usr/bin/python3",
            "-c",
            script,
        ],
        stdout=stdout_handle,
        stderr=stderr_handle,
    )
    stdout_handle.close()
    stderr_handle.close()
    time.sleep(0.25)
    exit_code = process.poll()
    if exit_code is not None and exit_code != 0:
        detail = stderr_path.read_text(encoding="utf-8", errors="replace")[:2048]
        raise RuntimeError(
            f"second successor peer-B service failed: exit={exit_code}; stderr={detail!r}"
        )
    return process


def _continue_from_midpoint(
    args: argparse.Namespace,
    *,
    ledger_path: Path,
    ledger: JsonObject,
) -> tuple[JsonObject, subprocess.Popen[bytes]]:
    validated = _validated_range_ledger(
        args.state_root,
        args.state_root / "runs",
        ledger_path,
        ledger,
    )
    if validated is None:
        raise RuntimeError("second successor refuses unsafe inherited ledger")
    run_path, namespaces, host_links, _ = validated
    if len(namespaces) != 3 or len(host_links) != 2:
        raise RuntimeError("second successor expected exact S6 identities")
    fabric_ns, _, peer_ns = namespaces
    peer_veth, fabric_veth = host_links
    bridge_name = ledger.get("bridgeName")
    tap_name = ledger.get("tapName")
    if not isinstance(bridge_name, str) or not isinstance(tap_name, str):
        raise RuntimeError("second successor lacks bridge/TAP identity")

    before = _mid_world_truth(ledger)
    if before.get("exactMidpoint") is not True:
        raise RuntimeError("second successor did not observe the accepted midpoint")

    _run(["/usr/bin/ip", "-n", fabric_ns, "link", "set", fabric_veth, "up"])
    _run(["/usr/bin/ip", "-n", peer_ns, "link", "set", "lo", "up"])
    _run(["/usr/bin/ip", "-n", peer_ns, "link", "set", peer_veth, "up"])
    addresses_before = _namespace_addresses(peer_ns, peer_veth)
    wanted_address = f"{_PEER_B_ADDRESS}/{_PREFIX_LENGTH}"
    if wanted_address not in addresses_before:
        _run(
            [
                "/usr/bin/ip",
                "-n",
                peer_ns,
                "addr",
                "add",
                wanted_address,
                "dev",
                peer_veth,
            ]
        )
    routes = _peer_route_truth(peer_ns)
    if routes.get("defaultRouteAbsent") is not True:
        raise RuntimeError("second successor observed an unexpected peer-B default route")
    addresses = _namespace_addresses(peer_ns, peer_veth)
    if wanted_address not in addresses:
        raise RuntimeError("second successor did not establish peer-B address")
    bridge = _bridge_truth(fabric_namespace=fabric_ns, bridge_name=bridge_name)
    if set(cast(list[str], bridge.get("portNames", []))) != {tap_name, fabric_veth}:
        raise RuntimeError("second successor lost expected bridge placement")
    if bridge.get("bridgeL3AddressCount") != 0 or bridge.get("externalRouteAbsent") is not True:
        raise RuntimeError("second successor violated isolated fabric L3 truth")
    if _root_link_truth(names=host_links).get("presentNames") != []:
        raise RuntimeError("second successor found unexpected root veth residuals")

    peer_process = _start_peer_b_service(run_path, peer_ns)
    exit_code = peer_process.poll()
    if exit_code == 0:
        peer_pid = 0
        peer_start = None
    else:
        peer_pid = peer_process.pid
        peer_start = _process_start_time(peer_pid)
        if peer_start is None:
            peer_process.terminate()
            raise RuntimeError("second successor cannot observe peer-B process identity")
    continued = _persist_continued_ledger(
        ledger_path=ledger_path,
        ledger=ledger,
        peer_namespace=peer_ns,
        peer_pid=peer_pid,
        peer_start_time=peer_start,
    )
    after = _mid_world_truth(continued)
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.mid-successor-second-continuation",
        "sourceTopologyPhase": ledger.get("topologyPhase"),
        "targetTopologyPhase": continued.get("topologyPhase"),
        "beforeWorldTruth": before,
        "afterWorldTruth": after,
        "durableLedger": {
            "topologyPhase": continued.get("topologyPhase"),
            "currentPeerAddress": continued.get("currentPeerAddress"),
            "peerNamespace": continued.get("peerNamespace"),
            "peerPid": continued.get("peerPid"),
            "peerStartTime": continued.get("peerStartTime"),
        },
        "wholeEffectReplayAttempted": False,
        "physicalSuffixMutationAttempted": True,
    }
    validate_json(result)
    return result, peer_process


def _second_successor(args: argparse.Namespace) -> None:
    ledger_path, ledger, ledger_bytes = _one_ledger(args.state_root, "second successor")
    digest = _digest_bytes(ledger_bytes)
    claim = acquire_windows_fabric_successor_claim(
        args.state_root,
        ledger_path=ledger_path,
        expected_ledger_digest=digest,
        purpose="mid-successor-second",
    )
    if claim is None:
        raise RuntimeError("second successor failed to acquire recovery authority")
    try:
        before = _mid_world_truth(ledger)
        history = read_windows_fabric_recovery_claim_history(
            args.state_root,
            run_token=ledger_path.stem,
        )
        result: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.mid-successor-second-result",
            "status": "unknown",
            "observedLedgerDigest": digest,
            "claim": claim.claim,
            "claimHistory": history,
            "worldTruthBeforeContinuation": before,
            "startedAtNs": time.time_ns(),
        }
        continuation, peer_process = _continue_from_midpoint(
            args,
            ledger_path=ledger_path,
            ledger=ledger,
        )
        continued_ledger = _load_object(ledger_path, "second successor continued ledger")
        qemu_pid = continued_ledger.get("qemuPid")
        qemu_start = continued_ledger.get("qemuStartTime")
        if not isinstance(qemu_pid, int) or not isinstance(qemu_start, int):
            raise RuntimeError("second successor lacks exact QEMU identity")
        guest_completed = _wait_identity_gone(
            pid=qemu_pid,
            start_time=qemu_start,
            timeout_seconds=args.guest_timeout_seconds,
        )
        if not guest_completed:
            raise TimeoutError("Guest did not complete after second-successor continuation")
        peer_exit = peer_process.poll()
        if peer_exit is None:
            peer_exit = peer_process.wait(timeout=10)
        run_path = Path(cast(str, continued_ledger["runPath"]))
        guest_claim = _extract_guest_claim(run_path=run_path)
        capture_pid = continued_ledger.get("capturePid")
        capture_start = continued_ledger.get("captureStartTime")
        if not isinstance(capture_pid, int) or not isinstance(capture_start, int):
            raise RuntimeError("second successor lacks exact capture identity")
        sensor = _sensor_truth(
            run_path=run_path,
            capture_pid=capture_pid,
            capture_start_time=capture_start,
        )
        result["status"] = "continued-from-midpoint"
        result["continuation"] = continuation
        result["continuedLedgerDigest"] = _digest_bytes(ledger_path.read_bytes())
        result["guestCompleted"] = guest_completed
        result["guestClaim"] = guest_claim
        result["sensorObservation"] = sensor
        result["peerExitCode"] = peer_exit
        result["finishedAtNs"] = time.time_ns()
        _write_private(args.second_result, result)
        while True:
            time.sleep(1)
    finally:
        claim.release(disposition="released-by-second-successor")


def _worker_command(args: argparse.Namespace, role: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_mid_successor_recovery_acceptance",
        f"--{role}",
        "--base-manifest",
        str(args.base_manifest),
        "--state-root",
        str(args.state_root),
        "--gate",
        str(args.gate),
        "--token",
        args.token,
        "--first-ready",
        str(args.first_ready),
        "--first-continue-gate",
        str(args.first_continue_gate),
        "--midpoint-gate",
        str(args.midpoint_gate),
        "--second-result",
        str(args.second_result),
        "--final-reconciler-result",
        str(args.final_reconciler_result),
        "--memory-mib",
        str(args.memory_mib),
        "--vcpus",
        str(args.vcpus),
        "--stage-timeout-seconds",
        str(args.stage_timeout_seconds),
        "--guest-timeout-seconds",
        str(args.guest_timeout_seconds),
    ]


def _supervisor(args: argparse.Namespace) -> None:
    revision = _git_revision(Path.cwd(), "Security")
    args.state_root.mkdir(parents=True, exist_ok=False)
    args.state_root.chmod(0o755)
    args.gate.parent.mkdir(parents=True, exist_ok=True)
    args.first_ready.parent.mkdir(parents=True, exist_ok=True)

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
        raise TimeoutError("C1-G owner did not reach initial partial gate") from error
    if owner.returncode != -signal.SIGKILL:
        raise RuntimeError(f"C1-G owner did not die at injected gate: {owner.returncode}")

    ledger_path, inherited, inherited_bytes = _one_ledger(args.state_root, "C1-G supervisor")
    inherited_digest = _digest_bytes(inherited_bytes)
    semantic_binding = _ledger_semantic_binding(inherited)

    first = subprocess.Popen(
        _worker_command(args, "first-successor"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for_path(args.first_ready, timeout_seconds=args.stage_timeout_seconds)
    first_ready = _load_object(args.first_ready, "first successor ready")
    _write_private(
        args.first_continue_gate,
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.mid-successor-release-first",
            "releasedAtNs": time.time_ns(),
        },
    )
    _wait_for_path(args.midpoint_gate, timeout_seconds=args.stage_timeout_seconds)
    midpoint = _load_object(args.midpoint_gate, "first successor midpoint")
    first_out, first_err = first.communicate(timeout=15)
    if first.returncode != -signal.SIGKILL:
        raise RuntimeError(f"first successor did not die by SIGKILL: {first.returncode}")
    after_first_path, after_first, after_first_bytes = _one_ledger(
        args.state_root, "post-first-successor"
    )
    after_first_digest = _digest_bytes(after_first_bytes)
    first_claim = midpoint.get("claim")
    if not isinstance(first_claim, dict):
        raise RuntimeError("first midpoint lacks claim")

    second = subprocess.Popen(
        _worker_command(args, "second-successor"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for_path(args.second_result, timeout_seconds=args.guest_timeout_seconds + 90)
    second_result = _load_object(args.second_result, "second successor result")
    if second_result.get("status") != "continued-from-midpoint":
        second.kill()
        second.communicate(timeout=10)
        raise RuntimeError(f"second successor failed: {second_result}")
    continued_path, continued, continued_bytes = _one_ledger(
        args.state_root, "post-second-successor"
    )
    continued_digest = _digest_bytes(continued_bytes)
    second_claim = second_result.get("claim")
    if not isinstance(second_claim, dict):
        second.kill()
        second.communicate(timeout=10)
        raise RuntimeError("second successor result lacks claim")
    history = second_result.get("claimHistory")
    if not isinstance(history, list):
        second.kill()
        second.communicate(timeout=10)
        raise RuntimeError("second successor result lacks claim history")

    second_pid = second_claim.get("claimantPid")
    second_start = second_claim.get("claimantStartTime")
    second.kill()
    second_out, second_err = second.communicate(timeout=15)
    second_dead = not _identity_alive(second_pid, second_start)

    final_reconcile = reconcile_windows_fabric_range_runs(
        args.state_root,
        receipt_path=args.final_reconciler_result,
    )
    final_result = (
        final_reconcile["results"][0]
        if isinstance(final_reconcile.get("results"), list) and final_reconcile["results"]
        else {}
    )
    final_process = _process_truth(continued)
    final_namespace = _host_namespace_truth(continued)
    _, peer_veth, fabric_veth = _link_names(cast(str, continued["rangeSessionId"]))
    final_root = _root_link_truth(names=(peer_veth, fabric_veth))
    final_ledger_count = len(list((args.state_root / "run-ledgers").glob("*.json")))
    cleanup = _exact_cleanup(args, continued)

    first_claim_id = first_claim.get("claimId")
    history_has_first = any(
        isinstance(item, dict) and item.get("claimId") == first_claim_id for item in history
    )
    same_durable_generation_different_world = (
        inherited_digest == after_first_digest
        and midpoint.get("ledgerDigestBeforeMutation") == inherited_digest
        and midpoint.get("ledgerDigestAtKill") == inherited_digest
        and isinstance(midpoint.get("worldTruth"), dict)
        and cast(dict[str, object], midpoint["worldTruth"]).get("exactMidpoint") is True
    )
    guest_claim = second_result.get("guestClaim")
    sensor = second_result.get("sensorObservation")
    gates = {
        "originalOwnerKilledAtInitialPartialGate": owner.returncode == -signal.SIGKILL,
        "firstSuccessorAcquiredAuthority": first_ready.get("ledgerDigest") == inherited_digest
        and isinstance(first_ready.get("claim"), dict),
        "firstSuccessorDiedAtMidContinuation": first.returncode == -signal.SIGKILL
        and midpoint.get("faultPoint") == _MID_FAULT,
        "sameLedgerDigestContainedDifferentPhysicalProgress": (
            same_durable_generation_different_world
        ),
        "semanticEffectIdentitySurvivedFirstSuccessorCrash": _ledger_semantic_binding(after_first)
        == semantic_binding,
        "secondSuccessorClaimedSameDurableGeneration": second_result.get("observedLedgerDigest")
        == inherited_digest
        and second_claim.get("ledgerDigest") == inherited_digest,
        "secondSuccessorPreservedFirstClaimLineage": second_claim.get("predecessorClaimId")
        == first_claim_id
        and history_has_first,
        "secondSuccessorReobservedMidpointWorld": isinstance(
            second_result.get("worldTruthBeforeContinuation"), dict
        )
        and cast(dict[str, object], second_result["worldTruthBeforeContinuation"]).get(
            "exactMidpoint"
        )
        is True,
        "secondSuccessorContinuedOnlyMissingSuffix": second_result.get("status")
        == "continued-from-midpoint"
        and isinstance(second_result.get("continuation"), dict)
        and cast(dict[str, object], second_result["continuation"]).get("wholeEffectReplayAttempted")
        is False,
        "secondSuccessorPublishedStableGeneration": continued_digest != inherited_digest
        and continued.get("topologyPhase") == "peer-b-present"
        and continued.get("currentPeerAddress") == _PEER_B_ADDRESS,
        "sameGuestCompletedAcrossTwoControllerDeaths": isinstance(guest_claim, dict)
        and _guest_claim_passes(cast(JsonObject, guest_claim)),
        "sensorObservedAAndBFlowsAcrossSuccession": isinstance(sensor, dict)
        and sensor.get("peerATrafficObserved") is True
        and sensor.get("peerBTrafficObserved") is True,
        "secondSuccessorSigkillReleasedAuthority": second.returncode == -signal.SIGKILL
        and second_dead,
        "finalReconcilerPreservedRecoveryLineage": isinstance(final_result, dict)
        and isinstance(final_result.get("successorClaimObserved"), dict)
        and cast(dict[str, object], final_result["successorClaimObserved"]).get("claimId")
        == second_claim.get("claimId")
        and isinstance(final_result.get("successorClaimHistoryObserved"), list)
        and any(
            isinstance(item, dict) and item.get("claimId") == first_claim_id
            for item in cast(list[object], final_result["successorClaimHistoryObserved"])
        ),
        "finalReconcilerClosedWorld": final_reconcile.get("reconciled") == 1
        and final_ledger_count == 0
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
        "kind": "ordivon.security.mid-successor-recovery-acceptance",
        "status": "accepted" if passed else "failed",
        "securityRevision": revision,
        "initialFaultPoint": _FAULT_POINT,
        "successorFaultPoint": _MID_FAULT,
        "owner": {
            "returnCode": owner.returncode,
            "stdoutTail": owner_out[-1500:],
            "stderrTail": owner_err[-1500:],
        },
        "inherited": {
            "ledgerDigest": inherited_digest,
            "semanticEffectBinding": semantic_binding,
        },
        "firstSuccessor": {
            "ready": first_ready,
            "midpoint": midpoint,
            "returnCode": first.returncode,
            "stdoutTail": first_out[-1500:],
            "stderrTail": first_err[-1500:],
            "postCrashLedgerDigest": after_first_digest,
        },
        "secondSuccessor": {
            "result": second_result,
            "continuedLedgerDigest": continued_digest,
            "returnCode": second.returncode,
            "stdoutTail": second_out[-1500:],
            "stderrTail": second_err[-1500:],
        },
        "finalReconciliation": final_reconcile,
        "finalTruth": {
            "ledgerCount": final_ledger_count,
            "processTruth": final_process,
            "namespaceTruth": final_namespace,
            "rootLinkTruth": final_root,
        },
        "experimentCleanup": cleanup,
        "gates": gates,
        "interpretation": {
            "durableLedgerDigestEqualsPhysicalWorldProgress": False,
            "worldObservationRequiredAfterAuthorityAcquisition": True,
            "durableSubstepStateConsumed": False,
            "wholeEffectReplayRequired": False,
            "recoveryClaimLineageSufficientForTestedSuccession": True,
            "genericCausalDagRequired": False,
        },
    }
    _write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if not passed:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Kill one successor after partial physical continuation, then require another "
            "successor to re-observe and finish without durable substep state."
        )
    )
    parser.add_argument("--first-successor", action="store_true")
    parser.add_argument("--second-successor", action="store_true")
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--token", default="mid-successor")
    parser.add_argument("--first-ready", type=Path, required=True)
    parser.add_argument("--first-continue-gate", type=Path, required=True)
    parser.add_argument("--midpoint-gate", type=Path, required=True)
    parser.add_argument("--second-result", type=Path, required=True)
    parser.add_argument("--final-reconciler-result", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--max-runtime-seconds", type=int, default=360)
    parser.add_argument("--owner-wait-seconds", type=float, default=180.0)
    parser.add_argument("--stage-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--guest-timeout-seconds", type=float, default=180.0)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.first_successor:
        _first_successor(args)
        return
    if args.second_successor:
        _second_successor(args)
        return
    if args.receipt is None:
        raise ValueError("C1-G supervisor requires --receipt")
    _supervisor(args)


if __name__ == "__main__":
    main()
