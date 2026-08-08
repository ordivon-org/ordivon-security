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
    _namespace_addresses,
    _namespace_link_names,
    _peer_route_truth,
)
from ordivon_security.cli_windows_kvm_partial_materialization_acceptance import (
    _FAULT_POINT,
    _link_names,
    _root_link_truth,
)
from ordivon_security.cli_windows_kvm_s3_acceptance import _write_receipt
from ordivon_security.cli_windows_kvm_successor_ownership_acceptance import _exact_cleanup
from ordivon_security.cli_windows_kvm_successor_reconciler_race_acceptance import (
    _successor_preflight,
    _wait_for_path,
    _write_private,
)
from ordivon_security.providers.windows_kvm import _load_object
from ordivon_security.range.windows_fabric_reconcile import (
    _identity_alive,
    reconcile_windows_fabric_range_runs,
)
from ordivon_security.range.windows_fabric_recovery_ownership import (
    RecoveryClaimStaleError,
    acquire_windows_fabric_successor_claim,
)


def _one_ledger(state_root: Path, label: str) -> tuple[Path, JsonObject, bytes]:
    ledgers = sorted((state_root / "run-ledgers").glob("*.json"))
    if len(ledgers) != 1:
        raise RuntimeError(f"{label} expected one exact Range ledger, found {len(ledgers)}")
    path = ledgers[0]
    raw = path.read_bytes()
    return path, _load_object(path, f"{label} Range ledger"), raw


def _stable_peer_b_truth(ledger: JsonObject) -> JsonObject:
    session_id = ledger.get("rangeSessionId")
    if not isinstance(session_id, str):
        raise RuntimeError("successor retry lacks rangeSessionId")
    peer_ns, peer_veth, fabric_veth = _link_names(session_id)
    fabric_ns = ledger.get("fabricNamespace")
    bridge_name = ledger.get("bridgeName")
    tap_name = ledger.get("tapName")
    if not all(isinstance(value, str) for value in (fabric_ns, bridge_name, tap_name)):
        raise RuntimeError("successor retry lacks durable fabric identity")
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
    stable = (
        ledger.get("topologyPhase") == "peer-b-present"
        and ledger.get("currentPeerAddress") == "10.253.70.4"
        and process_truth.get("qemuAlive") is True
        and process_truth.get("swtpmAlive") is True
        and process_truth.get("captureAlive") is True
        and set(cast(list[str], namespace_truth.get("ownedNamespacesPresent", [])))
        == {cast(str, fabric_ns), peer_ns}
        and peer_veth in peer_links
        and fabric_veth in fabric_links
        and set(cast(list[str], bridge_truth.get("portNames", [])))
        == {cast(str, tap_name), fabric_veth}
        and "10.253.70.4/24" in addresses
        and routes.get("defaultRouteAbsent") is True
        and root_truth.get("presentNames") == []
    )
    truth: JsonObject = {
        "authority": "host-observed-stable-peer-b-world",
        "stable": stable,
        "topologyPhase": ledger.get("topologyPhase"),
        "currentPeerAddress": ledger.get("currentPeerAddress"),
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


def _worker(args: argparse.Namespace) -> None:
    ledger_path, ledger, ledger_bytes = _one_ledger(args.state_root, f"successor {args.label}")
    initial_digest = _digest_bytes(ledger_bytes)
    _wait_for_path(args.start_gate, timeout_seconds=args.race_timeout_seconds)
    claim = acquire_windows_fabric_successor_claim(
        args.state_root,
        ledger_path=ledger_path,
        expected_ledger_digest=initial_digest,
        purpose=f"multiple-successor-{args.label}-initial",
    )
    if claim is None:
        lost: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.multiple-successor-attempt",
            "label": args.label,
            "status": "lost-authority",
            "observedLedgerDigest": initial_digest,
            "recordedAtNs": time.time_ns(),
        }
        _write_private(args.attempt_result, lost)
        _wait_for_path(args.retry_gate, timeout_seconds=args.retry_timeout_seconds)
        retry_path, retry_ledger, retry_bytes = _one_ledger(
            args.state_root, f"successor {args.label} retry"
        )
        retry_digest = _digest_bytes(retry_bytes)
        try:
            retry_claim = acquire_windows_fabric_successor_claim(
                args.state_root,
                ledger_path=retry_path,
                expected_ledger_digest=retry_digest,
                purpose=f"multiple-successor-{args.label}-retry",
            )
        except RecoveryClaimStaleError as error:
            result: JsonObject = {
                "schemaVersion": 1,
                "kind": "ordivon.security.multiple-successor-retry",
                "label": args.label,
                "status": "stale-generation",
                "observedLedgerDigest": retry_digest,
                "error": str(error),
            }
            _write_private(args.retry_result, result)
            return
        if retry_claim is None:
            result = {
                "schemaVersion": 1,
                "kind": "ordivon.security.multiple-successor-retry",
                "label": args.label,
                "status": "lost-authority-again",
                "observedLedgerDigest": retry_digest,
            }
            _write_private(args.retry_result, cast(JsonObject, result))
            return
        try:
            stable = _stable_peer_b_truth(retry_ledger)
            result = {
                "schemaVersion": 1,
                "kind": "ordivon.security.multiple-successor-retry",
                "label": args.label,
                "status": "adopted-existing-effect"
                if stable.get("stable") is True
                else "unknown-world",
                "observedLedgerDigest": retry_digest,
                "claim": retry_claim.claim,
                "worldTruth": stable,
                "wholeEffectReplayAttempted": False,
                "physicalMutationAttempted": False,
                "recordedAtNs": time.time_ns(),
            }
            _write_private(args.retry_result, cast(JsonObject, result))
            while True:
                time.sleep(1)
        finally:
            retry_claim.release(disposition="released-by-retry-successor")
        return

    try:
        preflight = _successor_preflight(args, ledger_path, ledger)
        won: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.multiple-successor-attempt",
            "label": args.label,
            "status": "acquired-authority",
            "observedLedgerDigest": initial_digest,
            "claim": claim.claim,
            "preflight": preflight,
            "recordedAtNs": time.time_ns(),
        }
        _write_private(args.attempt_result, won)
        _wait_for_path(args.continue_gate, timeout_seconds=args.race_timeout_seconds)
        result: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.multiple-successor-winner-continuation",
            "label": args.label,
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
            _write_private(args.winner_result, result)
            while True:
                time.sleep(1)
        except BaseException as error:
            result["status"] = "failed"
            result["errorType"] = type(error).__name__
            result["errorMessage"] = str(error)
            result["finishedAtNs"] = time.time_ns()
            _write_private(args.winner_result, result)
            raise
    finally:
        claim.release(disposition="released-by-initial-successor")


def _worker_command(args: argparse.Namespace, label: str) -> list[str]:
    suffix = label.lower()
    return [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_multiple_successors_acceptance",
        "--worker",
        "--label",
        label,
        "--base-manifest",
        str(args.base_manifest),
        "--state-root",
        str(args.state_root),
        "--gate",
        str(args.gate),
        "--token",
        args.token,
        "--start-gate",
        str(args.start_gate),
        "--continue-gate",
        str(args.continue_gate),
        "--retry-gate",
        str(args.retry_gate),
        "--attempt-result",
        str(args.experiment_root / f"{suffix}-attempt.json"),
        "--winner-result",
        str(args.experiment_root / f"{suffix}-winner.json"),
        "--retry-result",
        str(args.experiment_root / f"{suffix}-retry.json"),
        "--memory-mib",
        str(args.memory_mib),
        "--vcpus",
        str(args.vcpus),
        "--race-timeout-seconds",
        str(args.race_timeout_seconds),
        "--retry-timeout-seconds",
        str(args.retry_timeout_seconds),
    ]


def _supervisor(args: argparse.Namespace) -> None:
    revision = _git_revision(Path.cwd(), "Security")
    args.state_root.mkdir(parents=True, exist_ok=False)
    args.state_root.chmod(0o755)
    args.experiment_root.mkdir(parents=True, exist_ok=True)
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
        raise TimeoutError("multiple-successor owner did not reach partial kill gate") from error
    if owner.returncode != -signal.SIGKILL:
        raise RuntimeError(
            "multiple-successor owner did not die by SIGKILL: "
            f"returnCode={owner.returncode}; stdoutTail={owner_out[-3000:]!r}; "
            f"stderrTail={owner_err[-6000:]!r}"
        )

    ledger_path, inherited, inherited_bytes = _one_ledger(
        args.state_root, "multiple-successor supervisor"
    )
    inherited_digest = _digest_bytes(inherited_bytes)
    before_process = _process_truth(inherited)
    before_namespace = _host_namespace_truth(inherited)
    _, peer_veth, fabric_veth = _link_names(cast(str, inherited["rangeSessionId"]))
    before_root = _root_link_truth(names=(peer_veth, fabric_veth))

    workers: dict[str, subprocess.Popen[str]] = {}
    for label in ("A", "B"):
        workers[label] = subprocess.Popen(
            _worker_command(args, label),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    _write_private(
        args.start_gate,
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.multiple-successor-start",
            "releasedAtNs": time.time_ns(),
        },
    )
    attempts: dict[str, JsonObject] = {}
    for label in ("A", "B"):
        path = args.experiment_root / f"{label.lower()}-attempt.json"
        _wait_for_path(path, timeout_seconds=args.race_timeout_seconds)
        attempts[label] = _load_object(path, f"successor {label} initial attempt")
    winners = [
        label for label, value in attempts.items() if value.get("status") == "acquired-authority"
    ]
    losers = [label for label, value in attempts.items() if value.get("status") == "lost-authority"]
    if len(winners) != 1 or len(losers) != 1:
        for worker in workers.values():
            worker.kill()
        raise RuntimeError(f"expected one winner/one loser, got winners={winners} losers={losers}")
    winner = winners[0]
    loser = losers[0]
    after_competition_process = _process_truth(inherited)
    after_competition_namespace = _host_namespace_truth(inherited)
    after_competition_root = _root_link_truth(names=(peer_veth, fabric_veth))
    first_claim = cast(JsonObject, attempts[winner]["claim"])

    _write_private(
        args.continue_gate,
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.multiple-successor-winner-continue",
            "winner": winner,
            "releasedAtNs": time.time_ns(),
        },
    )
    winner_result_path = args.experiment_root / f"{winner.lower()}-winner.json"
    _wait_for_path(winner_result_path, timeout_seconds=args.race_timeout_seconds)
    winner_result = _load_object(winner_result_path, "multiple-successor winner result")
    if winner_result.get("status") != "continued":
        for worker in workers.values():
            worker.kill()
        raise RuntimeError(f"winner failed continuation: {winner_result}")
    current_path, current_ledger, current_bytes = _one_ledger(
        args.state_root, "post-winner continuation"
    )
    current_digest = _digest_bytes(current_bytes)
    winner_world = _stable_peer_b_truth(current_ledger)
    claim_path = args.state_root / "recovery-claims" / f"{ledger_path.stem}.json"
    winner_claim_on_disk = _load_object(claim_path, "winner durable claim")

    winner_process = workers[winner]
    winner_process.kill()
    winner_out, winner_err = winner_process.communicate(timeout=15)
    winner_dead = not _identity_alive(
        first_claim.get("claimantPid"), first_claim.get("claimantStartTime")
    )
    stale_winner_claim = _load_object(claim_path, "stale winner claim")

    _write_private(
        args.retry_gate,
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.multiple-successor-loser-retry",
            "loser": loser,
            "releasedAtNs": time.time_ns(),
        },
    )
    retry_path = args.experiment_root / f"{loser.lower()}-retry.json"
    _wait_for_path(retry_path, timeout_seconds=args.retry_timeout_seconds)
    retry = _load_object(retry_path, "losing successor retry")
    retry_claim_raw = retry.get("claim")
    if not isinstance(retry_claim_raw, dict):
        workers[loser].kill()
        workers[loser].communicate(timeout=15)
        raise RuntimeError(f"losing successor did not acquire retry authority: {retry}")
    retry_claim = cast(JsonObject, retry_claim_raw)
    current_claim_on_disk = _load_object(claim_path, "retry successor durable claim")
    lineage_fields = {
        "predecessorClaimId": current_claim_on_disk.get("predecessorClaimId"),
        "previousClaimId": current_claim_on_disk.get("previousClaimId"),
        "priorClaimId": current_claim_on_disk.get("priorClaimId"),
    }
    lineage_preserved = first_claim.get("claimId") in set(lineage_fields.values())

    loser_process = workers[loser]
    loser_process.kill()
    loser_out, loser_err = loser_process.communicate(timeout=15)
    loser_dead = not _identity_alive(
        retry_claim.get("claimantPid"), retry_claim.get("claimantStartTime")
    )
    stale_retry_claim = _load_object(claim_path, "stale retry claim")
    final_reconcile = reconcile_windows_fabric_range_runs(
        args.state_root, receipt_path=args.final_reconciler_result
    )
    final_ledger_count = len(list((args.state_root / "run-ledgers").glob("*.json")))
    final_process = _process_truth(current_ledger)
    final_namespace = _host_namespace_truth(current_ledger)
    final_root = _root_link_truth(names=(peer_veth, fabric_veth))
    cleanup = _exact_cleanup(args, current_ledger)

    gates = {
        "ownerKilledAtPartialGate": owner.returncode == -signal.SIGKILL,
        "bothSuccessorsObservedSameInitialGeneration": attempts["A"].get("observedLedgerDigest")
        == inherited_digest
        and attempts["B"].get("observedLedgerDigest") == inherited_digest,
        "exactlyOneInitialSuccessorAcquiredAuthority": len(winners) == 1 and len(losers) == 1,
        "losingSuccessorDidNotMutateInitialWorld": after_competition_process == before_process
        and after_competition_namespace == before_namespace
        and after_competition_root == before_root,
        "winnerContinuedEffect": winner_result.get("status") == "continued"
        and winner_world.get("stable") is True,
        "winnerChangedLedgerGeneration": current_digest != inherited_digest,
        "winnerSigkillReleasedAuthority": winner_process.returncode == -signal.SIGKILL
        and winner_dead,
        "loserRetriedAgainstCurrentGeneration": retry.get("observedLedgerDigest") == current_digest
        and retry_claim.get("ledgerDigest") == current_digest,
        "loserAdoptedExistingEffectWithoutReplay": retry.get("status") == "adopted-existing-effect"
        and retry.get("wholeEffectReplayAttempted") is False
        and retry.get("physicalMutationAttempted") is False,
        "loserBecameNextRecoveryAuthority": retry_claim.get("claimId")
        != first_claim.get("claimId"),
        "firstSuccessorClaimLineagePreserved": lineage_preserved,
        "retrySuccessorSigkillReleasedAuthority": loser_process.returncode == -signal.SIGKILL
        and loser_dead,
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
    only_lineage_failed = (
        all(value for key, value in gates.items() if key != "firstSuccessorClaimLineagePreserved")
        and not gates["firstSuccessorClaimLineagePreserved"]
    )
    status = (
        "lineage-falsifier-observed"
        if only_lineage_failed
        else ("accepted" if all(gates.values()) else "inconclusive")
    )
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.multiple-successors-baseline",
        "status": status,
        "securityRevision": revision,
        "faultPoint": _FAULT_POINT,
        "owner": {
            "returnCode": owner.returncode,
            "stdoutTail": owner_out[-1500:],
            "stderrTail": owner_err[-1500:],
        },
        "inheritedGeneration": {
            "ledgerDigest": inherited_digest,
            "semanticEffectBinding": _ledger_semantic_binding(inherited),
            "processTruth": before_process,
            "namespaceTruth": before_namespace,
            "rootLinkTruth": before_root,
        },
        "initialCompetition": {
            "attempts": attempts,
            "winner": winner,
            "loser": loser,
            "postCompetitionProcessTruth": after_competition_process,
            "postCompetitionNamespaceTruth": after_competition_namespace,
            "postCompetitionRootLinkTruth": after_competition_root,
        },
        "winnerContinuation": {
            "result": winner_result,
            "worldTruth": winner_world,
            "newLedgerDigest": current_digest,
            "claimOnDisk": winner_claim_on_disk,
        },
        "winnerCrash": {
            "returnCode": winner_process.returncode,
            "claimantDead": winner_dead,
            "staleClaim": stale_winner_claim,
            "stdoutTail": winner_out[-1500:],
            "stderrTail": winner_err[-1500:],
        },
        "loserRetry": {
            "result": retry,
            "claimOnDisk": current_claim_on_disk,
            "lineageFieldsObserved": lineage_fields,
            "firstClaimId": first_claim.get("claimId"),
            "lineagePreserved": lineage_preserved,
        },
        "loserCrash": {
            "returnCode": loser_process.returncode,
            "claimantDead": loser_dead,
            "staleClaim": stale_retry_claim,
            "stdoutTail": loser_out[-1500:],
            "stderrTail": loser_err[-1500:],
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
            "physicalMutualExclusionWorksForTwoSuccessors": gates[
                "exactlyOneInitialSuccessorAcquiredAuthority"
            ],
            "loserCanRetryCurrentGeneration": gates["loserRetriedAgainstCurrentGeneration"],
            "stableWorldCanBeAdoptedWithoutEffectReplay": gates[
                "loserAdoptedExistingEffectWithoutReplay"
            ],
            "durableSuccessorLineagePreserved": lineage_preserved,
            "genericPriorityPolicyRequired": False,
            "distributedConsensusRequired": False,
        },
    }
    _write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if status not in {"lineage-falsifier-observed", "accepted"}:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Physically test two S6 successor candidates over one dead-owner generation"
    )
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--label", choices=("A", "B"))
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--token", default="multiple-successors")
    parser.add_argument("--experiment-root", type=Path)
    parser.add_argument("--start-gate", type=Path, required=True)
    parser.add_argument("--continue-gate", type=Path, required=True)
    parser.add_argument("--retry-gate", type=Path, required=True)
    parser.add_argument("--attempt-result", type=Path)
    parser.add_argument("--winner-result", type=Path)
    parser.add_argument("--retry-result", type=Path)
    parser.add_argument("--final-reconciler-result", type=Path)
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--max-runtime-seconds", type=int, default=360)
    parser.add_argument("--owner-wait-seconds", type=float, default=180.0)
    parser.add_argument("--race-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--retry-timeout-seconds", type=float, default=90.0)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.worker:
        if (
            args.label is None
            or args.attempt_result is None
            or args.winner_result is None
            or args.retry_result is None
        ):
            raise ValueError("worker requires label and result paths")
        _worker(args)
        return
    if args.receipt is None or args.experiment_root is None or args.final_reconciler_result is None:
        raise ValueError("supervisor requires receipt, experiment root and final reconciler result")
    _supervisor(args)


if __name__ == "__main__":
    main()
