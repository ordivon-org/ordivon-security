from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
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
from ordivon_security.providers.windows_kvm import _load_object
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

_FAULT_POINT_COMPLETED_UNPUBLISHED = (
    "after-peer-b-consumed-and-guest-completed-before-stable-ledger-publication"
)


def _persistent_peer_b_topology(ledger: JsonObject) -> JsonObject:
    session_id = ledger.get("rangeSessionId")
    if not isinstance(session_id, str):
        raise RuntimeError("unpublished completion lacks rangeSessionId")
    peer_ns, peer_veth, fabric_veth = _link_names(session_id)
    fabric_ns = ledger.get("fabricNamespace")
    bridge_name = ledger.get("bridgeName")
    tap_name = ledger.get("tapName")
    if not all(isinstance(value, str) for value in (fabric_ns, bridge_name, tap_name)):
        raise RuntimeError("unpublished completion lacks durable fabric identity")
    namespace_truth = _host_namespace_truth(ledger)
    process_truth = _process_truth(ledger)
    peer_links = _namespace_link_names(peer_ns)
    fabric_links = _namespace_link_names(cast(str, fabric_ns))
    bridge_truth = _bridge_truth(
        fabric_namespace=cast(str, fabric_ns), bridge_name=cast(str, bridge_name)
    )
    addresses = _namespace_addresses(peer_ns, peer_veth)
    routes = _peer_route_truth(peer_ns)
    root_truth = _root_link_truth(names=(peer_veth, fabric_veth))
    complete = (
        set(cast(list[str], namespace_truth.get("ownedNamespacesPresent", [])))
        == {cast(str, fabric_ns), peer_ns}
        and peer_veth in peer_links
        and fabric_veth in fabric_links
        and set(cast(list[str], bridge_truth.get("portNames", [])))
        == {cast(str, tap_name), fabric_veth}
        and f"{_PEER_B_ADDRESS}/{_PREFIX_LENGTH}" in addresses
        and routes.get("defaultRouteAbsent") is True
        and root_truth.get("presentNames") == []
    )
    truth: JsonObject = {
        "authority": "host-observed-persistent-peer-b-topology",
        "complete": complete,
        "durableTopologyPhase": ledger.get("topologyPhase"),
        "durableCurrentPeerAddress": ledger.get("currentPeerAddress"),
        "processTruth": process_truth,
        "namespaceTruth": namespace_truth,
        "peerNamespaceLinks": peer_links,
        "fabricNamespaceLinks": fabric_links,
        "bridgeTruth": bridge_truth,
        "peerAddresses": addresses,
        "peerRoutes": routes,
        "rootLinkTruth": root_truth,
    }
    validate_json(truth)
    return truth


def _sensor_truth_read_only(
    *,
    run_path: Path,
    capture_pid: int,
    capture_start_time: int,
    tcpdump_path: Path = Path("/usr/bin/tcpdump"),
) -> JsonObject:
    """Read a point-in-time packet snapshot without changing capture process state."""
    time.sleep(0.5)
    capture_alive_before = _identity_alive(capture_pid, capture_start_time)
    pcap = run_path / "fabric.pcap"
    lines: list[str] = []
    digest: str | None = None
    snapshot_bytes = b""
    if pcap.is_file():
        snapshot_bytes = pcap.read_bytes()
        digest = _digest_bytes(snapshot_bytes)
        with tempfile.NamedTemporaryFile(suffix=".pcap") as snapshot:
            snapshot.write(snapshot_bytes)
            snapshot.flush()
            completed = subprocess.run(
                [str(tcpdump_path), "-nn", "-r", snapshot.name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
        lines = [
            line
            for line in completed.stdout.splitlines()
            if line.strip() and not line.startswith("reading from file ")
        ]
    capture_alive_after = _identity_alive(capture_pid, capture_start_time)
    truth: JsonObject = {
        "authority": "external-packet-sensor-read-only-observation-not-world-truth",
        "captureAliveBefore": capture_alive_before,
        "captureAliveAfter": capture_alive_after,
        "captureMutationAttempted": False,
        "pcapSnapshotByteLength": len(snapshot_bytes),
        "pcapDigest": digest,
        "packetLineCount": len(lines),
        "peerATrafficObserved": any(
            "10.253.70.2" in line and "10.253.70.3" in line for line in lines
        ),
        "peerBTrafficObserved": any(
            "10.253.70.2" in line and "10.253.70.4" in line for line in lines
        ),
        "sampleLines": lines[:24],
    }
    validate_json(truth)
    return truth


def _materialize_without_publication(
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
        raise RuntimeError("first successor refuses unsafe inherited ledger")
    run_path, namespaces, host_links, _ = validated
    if len(namespaces) != 3 or len(host_links) != 2:
        raise RuntimeError("first successor expected exact S6 identities")
    fabric_ns, _, peer_ns = namespaces
    peer_veth, fabric_veth = host_links
    bridge_name = ledger.get("bridgeName")
    tap_name = ledger.get("tapName")
    if not isinstance(bridge_name, str) or not isinstance(tap_name, str):
        raise RuntimeError("first successor lacks bridge/TAP identity")
    if (
        ledger.get("topologyPhase") != "peer-a-removed"
        or ledger.get("currentPeerAddress") is not None
    ):
        raise RuntimeError("first successor expected unpublished peer-a-removed durable state")

    preflight = _successor_preflight(args, ledger_path, ledger)
    if preflight.get("ready") is not True:
        raise RuntimeError("first successor preflight rejected inherited partial world")

    _run(["/usr/bin/ip", "link", "set", peer_veth, "netns", peer_ns])
    _run(["/usr/bin/ip", "link", "set", fabric_veth, "netns", fabric_ns])
    _run(["/usr/bin/ip", "-n", fabric_ns, "link", "set", fabric_veth, "master", bridge_name])
    _run(["/usr/bin/ip", "-n", fabric_ns, "link", "set", fabric_veth, "up"])
    _run(["/usr/bin/ip", "-n", peer_ns, "link", "set", "lo", "up"])
    _run(["/usr/bin/ip", "-n", peer_ns, "link", "set", peer_veth, "up"])
    _run(
        [
            "/usr/bin/ip",
            "-n",
            peer_ns,
            "addr",
            "add",
            f"{_PEER_B_ADDRESS}/{_PREFIX_LENGTH}",
            "dev",
            peer_veth,
        ]
    )
    topology = _persistent_peer_b_topology(ledger)
    if topology.get("complete") is not True:
        raise RuntimeError("first successor failed to materialize persistent peer-B topology")

    stdout_path = run_path / "peer-b.stdout.log"
    stderr_path = run_path / "peer-b.stderr.log"
    if stdout_path.exists() or stderr_path.exists():
        raise RuntimeError("first successor refuses pre-existing peer-B service logs")
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
    if process.poll() not in (None, 0):
        detail = stderr_path.read_text(encoding="utf-8", errors="replace")[:2048]
        raise RuntimeError(f"peer-B service failed before Guest consumption: {detail!r}")

    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.unpublished-completion-materialization",
        "preflight": preflight,
        "persistentTopology": topology,
        "durableLedgerDigestBefore": _digest_bytes(ledger_path.read_bytes()),
        "stablePublicationAttempted": False,
        "wholeEffectReplayAttempted": False,
    }
    validate_json(result)
    return result, process


def _first_successor(args: argparse.Namespace) -> None:
    ledger_path, ledger, ledger_bytes = _one_ledger(args.state_root, "C1-H first successor")
    digest = _digest_bytes(ledger_bytes)
    claim = acquire_windows_fabric_successor_claim(
        args.state_root,
        ledger_path=ledger_path,
        expected_ledger_digest=digest,
        purpose="unpublished-completion-first",
    )
    if claim is None:
        raise RuntimeError("C1-H first successor failed to acquire recovery authority")
    try:
        ready: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.unpublished-completion-first-ready",
            "claim": claim.claim,
            "ledgerDigest": digest,
            "recordedAtNs": time.time_ns(),
        }
        _write_private(args.first_ready, ready)
        _wait_for_path(args.first_continue_gate, timeout_seconds=args.stage_timeout_seconds)
        materialized, peer_process = _materialize_without_publication(
            args,
            ledger_path=ledger_path,
            ledger=ledger,
        )
        qemu_pid = ledger.get("qemuPid")
        qemu_start = ledger.get("qemuStartTime")
        if not isinstance(qemu_pid, int) or not isinstance(qemu_start, int):
            raise RuntimeError("C1-H first successor lacks exact QEMU identity")
        if not _wait_identity_gone(
            pid=qemu_pid,
            start_time=qemu_start,
            timeout_seconds=args.guest_timeout_seconds,
        ):
            peer_process.terminate()
            raise TimeoutError("C1-H Guest did not complete before unpublished-completion kill")
        peer_exit = peer_process.poll()
        if peer_exit is None:
            peer_exit = peer_process.wait(timeout=10)
        if peer_exit != 0:
            raise RuntimeError(
                f"C1-H peer-B one-shot service did not complete cleanly: {peer_exit}"
            )
        topology_after = _persistent_peer_b_topology(ledger)
        if topology_after.get("complete") is not True:
            raise RuntimeError("C1-H persistent peer-B topology disappeared before kill")
        gate: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.unpublished-completion-kill-gate",
            "faultPoint": _FAULT_POINT_COMPLETED_UNPUBLISHED,
            "claim": claim.claim,
            "ledgerDigestBeforeMaterialization": digest,
            "ledgerDigestAtKill": _digest_bytes(ledger_path.read_bytes()),
            "materialization": materialized,
            "persistentTopologyAtKill": topology_after,
            "peerServiceExitCode": peer_exit,
            "qemuGone": not _identity_alive(qemu_pid, qemu_start),
            "recordedAtNs": time.time_ns(),
        }
        _write_private(args.completion_gate, gate)
        os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError("C1-H first successor survived SIGKILL")
    finally:
        claim.release(disposition="released-by-unpublished-completion-first")


def _second_successor(args: argparse.Namespace) -> None:
    ledger_path, ledger, ledger_bytes = _one_ledger(args.state_root, "C1-H second successor")
    digest = _digest_bytes(ledger_bytes)
    claim = acquire_windows_fabric_successor_claim(
        args.state_root,
        ledger_path=ledger_path,
        expected_ledger_digest=digest,
        purpose="unpublished-completion-second",
    )
    if claim is None:
        raise RuntimeError("C1-H second successor failed to acquire recovery authority")
    try:
        topology = _persistent_peer_b_topology(ledger)
        run_path = Path(cast(str, ledger["runPath"]))
        guest_claim = _extract_guest_claim(run_path=run_path)
        capture_pid = ledger.get("capturePid")
        capture_start = ledger.get("captureStartTime")
        if not isinstance(capture_pid, int) or not isinstance(capture_start, int):
            raise RuntimeError("C1-H second successor lacks exact packet-sensor identity")
        sensor = _sensor_truth_read_only(
            run_path=run_path,
            capture_pid=capture_pid,
            capture_start_time=capture_start,
        )
        guest_complete = _guest_claim_passes(guest_claim)
        sensor_confirms_b = sensor.get("peerBTrafficObserved") is True
        durable_unpublished = (
            ledger.get("topologyPhase") == "peer-a-removed"
            and ledger.get("currentPeerAddress") is None
        )
        completed_but_unpublished = (
            topology.get("complete") is True
            and guest_complete
            and sensor_confirms_b
            and durable_unpublished
            and topology.get("processTruth", {}).get("peerAlive") is False
            and topology.get("processTruth", {}).get("qemuAlive") is False
        )
        if not completed_but_unpublished:
            raise RuntimeError(
                "C1-H second successor cannot prove completed-but-unpublished consequence"
            )
        continued = _persist_continued_ledger(
            ledger_path=ledger_path,
            ledger=ledger,
            peer_namespace=cast(str, ledger.get("ownedNamespaceCandidates", [None, None, None])[2]),
            peer_pid=0,
            peer_start_time=None,
        )
        history = read_windows_fabric_recovery_claim_history(
            args.state_root,
            run_token=ledger_path.stem,
        )
        result: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.unpublished-completion-second-result",
            "status": "repaired-publication-only",
            "observedLedgerDigest": digest,
            "claim": claim.claim,
            "claimHistory": history,
            "persistentTopology": topology,
            "guestClaim": guest_claim,
            "sensorObservation": sensor,
            "classification": "completed-but-unpublished",
            "transientPeerServiceRestarted": False,
            "wholeEffectReplayAttempted": False,
            "physicalMutationAttempted": False,
            "durablePublicationRepaired": True,
            "continuedLedgerDigest": _digest_bytes(ledger_path.read_bytes()),
            "continuedTopologyPhase": continued.get("topologyPhase"),
            "continuedCurrentPeerAddress": continued.get("currentPeerAddress"),
            "continuedPeerPid": continued.get("peerPid"),
            "continuedPeerStartTime": continued.get("peerStartTime"),
            "recordedAtNs": time.time_ns(),
        }
        _write_private(args.second_result, result)
        while True:
            time.sleep(1)
    finally:
        claim.release(disposition="released-by-unpublished-completion-second")


def _worker_command(args: argparse.Namespace, role: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_unpublished_completion_acceptance",
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
        "--completion-gate",
        str(args.completion_gate),
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
        raise TimeoutError("C1-H owner did not reach initial partial gate") from error
    if owner.returncode != -signal.SIGKILL:
        raise RuntimeError(f"C1-H owner did not die by SIGKILL: {owner.returncode}")

    ledger_path, inherited, inherited_bytes = _one_ledger(args.state_root, "C1-H supervisor")
    inherited_digest = _digest_bytes(inherited_bytes)
    semantic_binding = _ledger_semantic_binding(inherited)

    first = subprocess.Popen(
        _worker_command(args, "first-successor"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for_path(args.first_ready, timeout_seconds=args.stage_timeout_seconds)
    first_ready = _load_object(args.first_ready, "C1-H first successor ready")
    _write_private(
        args.first_continue_gate,
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.unpublished-completion-release-first",
            "releasedAtNs": time.time_ns(),
        },
    )
    _wait_for_path(args.completion_gate, timeout_seconds=args.guest_timeout_seconds + 90)
    completion_gate = _load_object(args.completion_gate, "C1-H completion kill gate")
    first_out, first_err = first.communicate(timeout=15)
    if first.returncode != -signal.SIGKILL:
        raise RuntimeError(f"C1-H first successor did not die by SIGKILL: {first.returncode}")

    after_first_path, after_first, after_first_bytes = _one_ledger(
        args.state_root, "C1-H post-first-successor"
    )
    after_first_digest = _digest_bytes(after_first_bytes)
    first_claim = completion_gate.get("claim")
    if not isinstance(first_claim, dict):
        raise RuntimeError("C1-H completion gate lacks first claim")

    second = subprocess.Popen(
        _worker_command(args, "second-successor"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for_path(args.second_result, timeout_seconds=args.stage_timeout_seconds + 90)
    second_result = _load_object(args.second_result, "C1-H second successor result")
    if second_result.get("status") != "repaired-publication-only":
        second.kill()
        second.communicate(timeout=10)
        raise RuntimeError(f"C1-H second successor failed: {second_result}")
    continued_path, continued, continued_bytes = _one_ledger(
        args.state_root, "C1-H continued ledger"
    )
    continued_digest = _digest_bytes(continued_bytes)
    second_claim = second_result.get("claim")
    if not isinstance(second_claim, dict):
        second.kill()
        second.communicate(timeout=10)
        raise RuntimeError("C1-H second result lacks claim")

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

    history = second_result.get("claimHistory")
    first_claim_id = first_claim.get("claimId")
    lineage_preserved = (
        second_claim.get("predecessorClaimId") == first_claim_id
        and isinstance(history, list)
        and any(
            isinstance(item, dict) and item.get("claimId") == first_claim_id for item in history
        )
    )
    guest_claim = second_result.get("guestClaim")
    sensor = second_result.get("sensorObservation")
    topology = second_result.get("persistentTopology")
    same_unpublished_digest = (
        inherited_digest == after_first_digest
        and completion_gate.get("ledgerDigestBeforeMaterialization") == inherited_digest
        and completion_gate.get("ledgerDigestAtKill") == inherited_digest
    )
    gates = {
        "originalOwnerKilledAtInitialPartialGate": owner.returncode == -signal.SIGKILL,
        "firstSuccessorAcquiredAuthority": isinstance(first_ready.get("claim"), dict)
        and first_ready.get("ledgerDigest") == inherited_digest,
        "firstSuccessorReachedCompletedUnpublishedFault": completion_gate.get("faultPoint")
        == _FAULT_POINT_COMPLETED_UNPUBLISHED
        and completion_gate.get("peerServiceExitCode") == 0
        and completion_gate.get("qemuGone") is True,
        "durableLedgerRemainedUnpublishedAfterCompletion": same_unpublished_digest
        and after_first.get("topologyPhase") == "peer-a-removed"
        and after_first.get("currentPeerAddress") is None,
        "semanticEffectIdentitySurvivedUnpublishedCompletion": _ledger_semantic_binding(after_first)
        == semantic_binding,
        "secondSuccessorClaimedSameDurableGeneration": second_result.get("observedLedgerDigest")
        == inherited_digest
        and second_claim.get("ledgerDigest") == inherited_digest,
        "secondSuccessorPreservedFirstClaimLineage": lineage_preserved,
        "secondSuccessorObservedPersistentPeerBTopology": isinstance(topology, dict)
        and topology.get("complete") is True,
        "secondSuccessorRecoveredGuestCompletionEvidence": isinstance(guest_claim, dict)
        and _guest_claim_passes(cast(JsonObject, guest_claim)),
        "secondSuccessorRecoveredIndependentPeerBSensorEvidence": isinstance(sensor, dict)
        and sensor.get("peerATrafficObserved") is True
        and sensor.get("peerBTrafficObserved") is True
        and sensor.get("captureAliveBefore") is True
        and sensor.get("captureAliveAfter") is True
        and sensor.get("captureMutationAttempted") is False,
        "secondSuccessorClassifiedCompletedButUnpublished": second_result.get("classification")
        == "completed-but-unpublished",
        "secondSuccessorDidNotRestartTransientPeerService": second_result.get(
            "transientPeerServiceRestarted"
        )
        is False,
        "secondSuccessorDidNotReplayOrPhysicallyMutate": second_result.get(
            "wholeEffectReplayAttempted"
        )
        is False
        and second_result.get("physicalMutationAttempted") is False,
        "secondSuccessorRepairedOnlyDurablePublication": second_result.get(
            "durablePublicationRepaired"
        )
        is True
        and continued_digest != inherited_digest
        and continued.get("topologyPhase") == "peer-b-present"
        and continued.get("currentPeerAddress") == _PEER_B_ADDRESS
        and continued.get("peerPid") == 0
        and continued.get("peerStartTime") is None,
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
        "kind": "ordivon.security.unpublished-completion-acceptance",
        "status": "accepted" if passed else "failed",
        "securityRevision": revision,
        "initialFaultPoint": _FAULT_POINT,
        "completionFaultPoint": _FAULT_POINT_COMPLETED_UNPUBLISHED,
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
            "completionGate": completion_gate,
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
            "completedConsequenceCanPrecedeDurableCompletionPublication": True,
            "transientExecutorLivenessRequiredForCompletionRecovery": False,
            "durableCompletionReceiptConsumed": False,
            "durableSubstepStateConsumed": False,
            "wholeEffectReplayRequired": False,
            "persistentTopologyPlusIndependentConsequenceEvidenceSufficient": passed,
            "genericExactlyOnceRequired": False,
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
            "Let peer B be consumed before stable publication, kill the successor, then "
            "recover completion from persistent topology plus independent consequence evidence."
        )
    )
    parser.add_argument("--first-successor", action="store_true")
    parser.add_argument("--second-successor", action="store_true")
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--token", default="unpublished-completion")
    parser.add_argument("--first-ready", type=Path, required=True)
    parser.add_argument("--first-continue-gate", type=Path, required=True)
    parser.add_argument("--completion-gate", type=Path, required=True)
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
        raise ValueError("C1-H supervisor requires --receipt")
    _supervisor(args)


if __name__ == "__main__":
    main()
