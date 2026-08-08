from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.cli_windows_kvm_c1a_acceptance import _git_revision
from ordivon_security.cli_windows_kvm_s3_acceptance import _write_receipt

_EFFECT_ID = "range-effect:c1k-idempotent-world-object-v1"
_REQUEST_ID = "range-effect-request:c1k-idempotent-world-object-v1"
_AUTHORITY_ID = "range-authority:c1k-local-idempotent-world"
_ACTOR_ID = "actor:c1k-recovery-sender"
_ZONE_REF = "zone:c1k-local-no-uplink"
_CAPABILITY = "world-object.ensure-state"
_EFFECT_TYPE = "world-object.ensure-exact-symlink"
_DESIRED_VALUE = "ordivon-world-state:c1k-idempotent-v1"
_TARGET_TOKEN = hashlib.sha256(_EFFECT_ID.encode()).hexdigest()[:24]
_TARGET_NAME = f"effect-{_TARGET_TOKEN}"


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _effect_binding() -> JsonObject:
    request: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1k-effect-request",
        "requestId": _REQUEST_ID,
        "actorId": _ACTOR_ID,
        "authorityId": _AUTHORITY_ID,
        "zoneRef": _ZONE_REF,
        "capability": _CAPABILITY,
        "effectType": _EFFECT_TYPE,
        "targetKey": _TARGET_NAME,
        "desiredValue": _DESIRED_VALUE,
    }
    request_digest = canonical_digest(request)
    admission: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1k-effect-admission",
        "requestId": _REQUEST_ID,
        "requestDigest": request_digest,
        "authorityId": _AUTHORITY_ID,
        "admitted": True,
    }
    result: JsonObject = {
        "actorId": _ACTOR_ID,
        "authorityId": _AUTHORITY_ID,
        "zoneRef": _ZONE_REF,
        "capability": _CAPABILITY,
        "effectType": _EFFECT_TYPE,
        "requestId": _REQUEST_ID,
        "requestDigest": request_digest,
        "admissionDigest": canonical_digest(admission),
        "effectId": _EFFECT_ID,
        "targetKey": _TARGET_NAME,
        "desiredValue": _DESIRED_VALUE,
    }
    validate_json(result)
    return result


def _sender_ledger() -> JsonObject:
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1k-sender-ledger",
        "effectBinding": _effect_binding(),
        "state": "admitted-pending-acknowledgement",
        "completionPublished": False,
    }
    validate_json(value)
    return value


def _atomic_sender_ledger(path: Path) -> bytes:
    value = _sender_ledger()
    data = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def _target_path(world_root: Path) -> Path:
    return world_root / _TARGET_NAME


def observe_world_target(world_root: Path) -> JsonObject:
    path = _target_path(world_root)
    if not os.path.lexists(path):
        value: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1k-world-target-observation",
            "targetKey": _TARGET_NAME,
            "present": False,
            "objectType": "absent",
            "desiredValue": _DESIRED_VALUE,
            "observedValue": None,
            "exactMatch": False,
            "semanticConsequenceCount": 0,
        }
        validate_json(value)
        return value
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode):
        observed = os.readlink(path)
        exact = observed == _DESIRED_VALUE
        object_type = "symlink"
    else:
        observed = None
        exact = False
        if stat.S_ISDIR(metadata.st_mode):
            object_type = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            object_type = "regular-file"
        else:
            object_type = "other"
    value = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1k-world-target-observation",
        "targetKey": _TARGET_NAME,
        "present": True,
        "objectType": object_type,
        "desiredValue": _DESIRED_VALUE,
        "observedValue": observed,
        "exactMatch": exact,
        "semanticConsequenceCount": 1 if exact else 0,
    }
    validate_json(value)
    return value


def ensure_world_target(world_root: Path) -> JsonObject:
    world_root.mkdir(parents=True, exist_ok=True)
    world_root.chmod(0o700)
    path = _target_path(world_root)
    before = observe_world_target(world_root)
    if before.get("exactMatch") is True:
        status_value = "already-satisfied"
        mutated = False
    elif before.get("present") is True:
        status_value = "conflict"
        mutated = False
    else:
        try:
            os.symlink(_DESIRED_VALUE, path)
            status_value = "applied"
            mutated = True
        except FileExistsError:
            concurrent = observe_world_target(world_root)
            if concurrent.get("exactMatch") is True:
                status_value = "already-satisfied"
                mutated = False
            else:
                status_value = "conflict"
                mutated = False
    after = observe_world_target(world_root)
    if status_value in {"applied", "already-satisfied"} and after.get("exactMatch") is not True:
        raise RuntimeError("C1-K successful ensure did not produce exact world consequence")
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1k-ensure-result",
        "effectId": _EFFECT_ID,
        "status": status_value,
        "worldMutated": mutated,
        "before": before,
        "after": after,
    }
    validate_json(result)
    return result


def _emit_oracle(fd: int, event: JsonObject) -> None:
    validate_json(event)
    os.write(fd, canonical_bytes(event) + b"\n")


def _recipient_main(args: argparse.Namespace) -> None:
    if args.socket_path is None or args.oracle_fd is None or args.world_root is None:
        raise ValueError("C1-K recipient requires socket/oracle/world-root")
    if args.recipient_mode is None:
        raise ValueError("C1-K recipient requires mode")
    socket_path = args.socket_path
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        server.bind(str(socket_path))
        socket_path.chmod(0o777)
        payload, client = server.recvfrom(65536)
        message = json.loads(payload)
        if not isinstance(message, dict) or message.get("effectId") != _EFFECT_ID:
            raise ValueError("C1-K recipient received wrong effect identity")
        received: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1k-invocation",
            "stage": "received",
            "effectId": _EFFECT_ID,
            "mode": args.recipient_mode,
        }
        _emit_oracle(args.oracle_fd, received)
        if args.recipient_mode == "crash-before-apply":
            os.kill(os.getpid(), signal.SIGKILL)
            raise RuntimeError("C1-K pre-apply recipient survived SIGKILL")
        if args.recipient_mode not in {"apply-crash-before-ack", "healthy"}:
            raise ValueError(f"unsupported C1-K recipient mode: {args.recipient_mode}")
        result = ensure_world_target(args.world_root)
        applied: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1k-invocation",
            "stage": "ensure-returned",
            "effectId": _EFFECT_ID,
            "mode": args.recipient_mode,
            "ensureStatus": result.get("status"),
            "worldMutated": result.get("worldMutated"),
        }
        _emit_oracle(args.oracle_fd, applied)
        if result.get("status") == "conflict":
            ack: JsonObject = {
                "schemaVersion": 1,
                "effectId": _EFFECT_ID,
                "status": "conflict",
            }
            if isinstance(client, str) and client:
                server.sendto(canonical_bytes(ack), client)
            return
        if args.recipient_mode == "apply-crash-before-ack":
            os.kill(os.getpid(), signal.SIGKILL)
            raise RuntimeError("C1-K post-apply recipient survived SIGKILL")
        ack = {
            "schemaVersion": 1,
            "effectId": _EFFECT_ID,
            "status": result.get("status"),
            "semanticEffectSatisfied": result.get("after", {}).get("exactMatch") is True,
        }
        if isinstance(client, str) and client:
            server.sendto(canonical_bytes(ack), client)
    finally:
        server.close()
        socket_path.unlink(missing_ok=True)


def _wait_socket(path: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists() and process.poll() is None:
            return
        if process.poll() is not None:
            raise RuntimeError(f"C1-K recipient exited before ready: {process.returncode}")
        time.sleep(0.02)
    raise TimeoutError("C1-K recipient socket did not become ready")


def _start_recipient(
    *, socket_path: Path, world_root: Path, mode: str
) -> tuple[subprocess.Popen[bytes], int]:
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_intrinsic_idempotency_acceptance",
            "--recipient",
            "--recipient-mode",
            mode,
            "--socket-path",
            str(socket_path),
            "--world-root",
            str(world_root),
            "--oracle-fd",
            str(write_fd),
        ],
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    _wait_socket(socket_path, process)
    return process, read_fd


def _read_oracle(read_fd: int) -> list[JsonObject]:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(read_fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(read_fd)
    events: list[JsonObject] = []
    for line in b"".join(chunks).splitlines():
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError("C1-K oracle event must be object")
        validate_json(item)
        events.append(cast(JsonObject, item))
    return events


def _collect_recipient(
    process: subprocess.Popen[bytes],
    read_fd: int,
    *,
    expected_sigkill: bool,
) -> tuple[list[JsonObject], JsonObject]:
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=10)
    events = _read_oracle(read_fd)
    expected = -signal.SIGKILL if expected_sigkill else 0
    if process.returncode != expected:
        raise RuntimeError(
            f"C1-K recipient exit {process.returncode}, expected {expected}: {stderr[-2048:]!r}"
        )
    truth: JsonObject = {
        "returnCode": process.returncode,
        "stdoutByteLength": len(stdout),
        "stderrByteLength": len(stderr),
        "oracleEvents": events,
    }
    validate_json(truth)
    return events, truth


def _restricted_send(*, socket_path: Path, client_path: Path) -> JsonObject:
    script = r"""
import json, os, socket, sys
socket_path, client_path, effect_id = sys.argv[1:4]
try: os.unlink(client_path)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
try:
    s.bind(client_path); s.settimeout(3)
    p=json.dumps({"schemaVersion":1,"effectId":effect_id},sort_keys=True,separators=(",",":")).encode()
    s.sendto(p,socket_path)
    try:
        b,_=s.recvfrom(65536); ack=json.loads(b); state="ack"
    except socket.timeout:
        ack=None; state="no-ack"
    print(json.dumps({"uid":os.geteuid(),"state":state,"ack":ack},sort_keys=True))
finally:
    s.close()
    try: os.unlink(client_path)
    except FileNotFoundError: pass
"""
    completed = subprocess.run(
        [
            "/usr/bin/setpriv",
            "--reuid",
            "65534",
            "--regid",
            "65534",
            "--clear-groups",
            "--",
            "/usr/bin/python3",
            "-c",
            script,
            str(socket_path),
            str(client_path),
            _EFFECT_ID,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"C1-K restricted send failed: {completed.stderr[-2048:]!r}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("C1-K restricted sender output must be object")
    validate_json(value)
    return cast(JsonObject, value)


def _world_tree(world_root: Path) -> JsonObject:
    entries: list[JsonObject] = []
    if world_root.exists():
        for child in sorted(world_root.iterdir(), key=lambda item: item.name):
            if child.is_symlink():
                item: JsonObject = {
                    "name": child.name,
                    "type": "symlink",
                    "target": os.readlink(child),
                }
            elif child.is_dir():
                item = {"name": child.name, "type": "directory"}
            elif child.is_file():
                item = {"name": child.name, "type": "regular-file"}
            else:
                item = {"name": child.name, "type": "other"}
            entries.append(item)
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1k-world-tree",
        "entries": entries,
    }
    validate_json(value)
    return value


def _run_history(
    *,
    root: Path,
    public_root: Path,
    history: str,
    preexisting: bool,
    first_mode: str,
) -> JsonObject:
    base = root / history
    world_root = base / "world"
    ledger_path = base / "sender-ledger.json"
    socket_path = public_root / f"{history}.sock"
    client_path = public_root / f"{history}-client.sock"
    ledger_bytes = _atomic_sender_ledger(ledger_path)
    world_root.mkdir(parents=True, exist_ok=True)
    world_root.chmod(0o700)
    setup_result: JsonObject | None = None
    if preexisting:
        setup_result = ensure_world_target(world_root)
        if setup_result.get("status") != "applied":
            raise RuntimeError("C1-K preexisting setup did not create exact target")
    before_first = observe_world_target(world_root)

    first, first_oracle_fd = _start_recipient(
        socket_path=socket_path,
        world_root=world_root,
        mode=first_mode,
    )
    first_send = _restricted_send(socket_path=socket_path, client_path=client_path)
    first_events, first_truth = _collect_recipient(
        first,
        first_oracle_fd,
        expected_sigkill=True,
    )
    socket_path.unlink(missing_ok=True)
    after_first = observe_world_target(world_root)
    tree_after_first = _world_tree(world_root)

    recovery, recovery_oracle_fd = _start_recipient(
        socket_path=socket_path,
        world_root=world_root,
        mode="healthy",
    )
    recovery_send = _restricted_send(socket_path=socket_path, client_path=client_path)
    recovery_events, recovery_truth = _collect_recipient(
        recovery,
        recovery_oracle_fd,
        expected_sigkill=False,
    )
    socket_path.unlink(missing_ok=True)
    final_observation = observe_world_target(world_root)
    final_tree = _world_tree(world_root)

    ensure_returns = [
        event for event in first_events + recovery_events if event.get("stage") == "ensure-returned"
    ]
    mutation_count = sum(event.get("worldMutated") is True for event in ensure_returns)
    invocation_count = sum(
        event.get("stage") == "received" for event in first_events + recovery_events
    )
    result: JsonObject = {
        "schemaVersion": 1,
        "history": history,
        "preexistingSetup": setup_result,
        "senderLedgerDigest": _digest_bytes(ledger_bytes),
        "senderLedgerUnchanged": ledger_path.read_bytes() == ledger_bytes,
        "beforeFirstAttempt": before_first,
        "firstAttempt": {
            "restrictedSend": first_send,
            "recipientTruth": first_truth,
            "worldAfterCrash": after_first,
            "worldTreeAfterCrash": tree_after_first,
        },
        "recoveryRetry": {
            "restrictedSend": recovery_send,
            "recipientTruth": recovery_truth,
            "worldAfterRetry": final_observation,
            "worldTreeAfterRetry": final_tree,
        },
        "physicalInvocationCount": invocation_count,
        "worldMutationCountByAcceptedEffect": mutation_count,
        "finalSemanticConsequenceCount": final_observation.get("semanticConsequenceCount"),
        "publicEndpointClosed": not socket_path.exists() and not client_path.exists(),
    }
    validate_json(result)
    return result


def _supervisor(args: argparse.Namespace) -> None:
    revision = _git_revision(Path.cwd(), "Security")
    if args.state_root is None or args.receipt is None:
        raise ValueError("C1-K supervisor requires state-root and receipt")
    args.state_root.mkdir(parents=True, exist_ok=False)
    public_root = Path("/tmp") / f"ordivon-c1k-{os.getpid()}"
    public_root.mkdir(mode=0o777)
    public_root.chmod(0o777)
    try:
        applied_then_lost_ack = _run_history(
            root=args.state_root,
            public_root=public_root,
            history="applied-then-ack-lost",
            preexisting=False,
            first_mode="apply-crash-before-ack",
        )
        absent_then_retry = _run_history(
            root=args.state_root,
            public_root=public_root,
            history="crash-before-apply",
            preexisting=False,
            first_mode="crash-before-apply",
        )
        preexisting_then_retry = _run_history(
            root=args.state_root,
            public_root=public_root,
            history="preexisting-exact-state",
            preexisting=True,
            first_mode="crash-before-apply",
        )

        applied_recovery = cast(dict[str, object], applied_then_lost_ack["recoveryRetry"])
        absent_recovery = cast(dict[str, object], absent_then_retry["recoveryRetry"])
        preexisting_recovery = cast(dict[str, object], preexisting_then_retry["recoveryRetry"])
        applied_ack = cast(dict[str, object], applied_recovery["restrictedSend"]).get("ack")
        absent_ack = cast(dict[str, object], absent_recovery["restrictedSend"]).get("ack")
        preexisting_ack = cast(dict[str, object], preexisting_recovery["restrictedSend"]).get("ack")
        applied_first = cast(dict[str, object], applied_then_lost_ack["firstAttempt"])
        absent_first = cast(dict[str, object], absent_then_retry["firstAttempt"])

        gates = {
            "appliedThenLostAckFirstAttemptMutatedWorld": cast(
                dict[str, object], applied_first["worldAfterCrash"]
            )["exactMatch"]
            is True,
            "appliedThenLostAckHadNoAck": cast(dict[str, object], applied_first["restrictedSend"])[
                "state"
            ]
            == "no-ack",
            "appliedThenLostAckRetryAlreadySatisfied": isinstance(applied_ack, dict)
            and applied_ack.get("status") == "already-satisfied",
            "appliedThenLostAckInvokedTwiceButMutatedOnce": applied_then_lost_ack.get(
                "physicalInvocationCount"
            )
            == 2
            and applied_then_lost_ack.get("worldMutationCountByAcceptedEffect") == 1,
            "appliedThenLostAckFinalSemanticConsequenceExactlyOne": applied_then_lost_ack.get(
                "finalSemanticConsequenceCount"
            )
            == 1,
            "crashBeforeApplyLeftWorldAbsent": cast(
                dict[str, object], absent_first["worldAfterCrash"]
            )["present"]
            is False,
            "crashBeforeApplyRetryApplied": isinstance(absent_ack, dict)
            and absent_ack.get("status") == "applied",
            "crashBeforeApplyFinalSemanticConsequenceExactlyOne": absent_then_retry.get(
                "finalSemanticConsequenceCount"
            )
            == 1,
            "preexistingStateSatisfiedBeforeInvocation": cast(
                dict[str, object], preexisting_then_retry["beforeFirstAttempt"]
            )["exactMatch"]
            is True,
            "preexistingStateRetryAlreadySatisfied": isinstance(preexisting_ack, dict)
            and preexisting_ack.get("status") == "already-satisfied",
            "preexistingStateRequestMutatedWorldZeroTimes": preexisting_then_retry.get(
                "worldMutationCountByAcceptedEffect"
            )
            == 0,
            "preexistingStateFinalSemanticConsequenceExactlyOne": preexisting_then_retry.get(
                "finalSemanticConsequenceCount"
            )
            == 1,
            "sameRetryPolicySafeAcrossPresentAndAbsentWorld": isinstance(applied_ack, dict)
            and isinstance(absent_ack, dict)
            and applied_ack.get("semanticEffectSatisfied") is True
            and absent_ack.get("semanticEffectSatisfied") is True,
            "effectBoundaryContainsNoAdjacentDedupOrInboxObject": all(
                len(
                    cast(
                        list[object],
                        cast(dict[str, object], history["recoveryRetry"])["worldTreeAfterRetry"][
                            "entries"
                        ],
                    )
                )
                == 1
                for history in (
                    applied_then_lost_ack,
                    absent_then_retry,
                    preexisting_then_retry,
                )
            ),
            "allSenderAttemptsUsedRestrictedUid": all(
                cast(dict[str, object], cast(dict[str, object], history[phase])["restrictedSend"])[
                    "uid"
                ]
                == 65534
                for history in (
                    applied_then_lost_ack,
                    absent_then_retry,
                    preexisting_then_retry,
                )
                for phase in ("firstAttempt", "recoveryRetry")
            ),
            "publicEndpointsClosed": all(
                history.get("publicEndpointClosed") is True
                for history in (
                    applied_then_lost_ack,
                    absent_then_retry,
                    preexisting_then_retry,
                )
            ),
            "noNetworkOrExternalTargetConsumed": True,
        }
        residual_entries = sorted(item.name for item in public_root.iterdir())
        gates["publicCapabilityRootClosedToZero"] = residual_entries == []
        passed = all(gates.values())
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1k-intrinsic-idempotency-acceptance",
            "status": "accepted" if passed else "failed",
            "securityRevision": revision,
            "effectBinding": _effect_binding(),
            "appliedThenAckLost": applied_then_lost_ack,
            "crashBeforeApply": absent_then_retry,
            "preexistingExactState": preexisting_then_retry,
            "gates": gates,
            "interpretation": {
                "repeatedInvocationCanConvergeToOneSemanticConsequence": passed,
                "exactlyOnceInvocationRequiredForThisEffect": False,
                "adjacentRecipientDedupRequiredForThisEffect": False,
                "semanticCompletionCanBeDefinedAsVerifiedInvariantSatisfaction": passed,
                "causalExecutionHistoryRequiredToVerifySatisfiedInvariant": False,
                "genericTransactionManagerRequired": False,
                "genericCausalDagRequired": False,
            },
        }
        _write_receipt(args.receipt, receipt)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
        if not passed:
            raise SystemExit(1)
    finally:
        if public_root.exists() and not any(public_root.iterdir()):
            public_root.rmdir()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run C1-K intrinsic-idempotency acceptance over one exact local world-state effect."
        )
    )
    parser.add_argument("--recipient", action="store_true")
    parser.add_argument(
        "--recipient-mode",
        choices=("apply-crash-before-ack", "crash-before-apply", "healthy"),
    )
    parser.add_argument("--socket-path", type=Path)
    parser.add_argument("--world-root", type=Path)
    parser.add_argument("--oracle-fd", type=int)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--receipt", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.recipient:
        _recipient_main(args)
        return
    _supervisor(args)


if __name__ == "__main__":
    main()
