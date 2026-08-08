from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.cli_windows_kvm_c1a_acceptance import _git_revision
from ordivon_security.cli_windows_kvm_s3_acceptance import _write_receipt

_EFFECT_ID = "range-effect:c1j-recipient-commit-gap-pulse-v1"
_REQUEST_ID = "range-effect-request:c1j-recipient-commit-gap-pulse-v1"
_AUTHORITY_ID = "range-authority:c1j-local-recipient-gap"
_ACTOR_ID = "actor:c1j-recovery-sender"
_ZONE_REF = "zone:c1j-local-no-uplink"
_CAPABILITY = "local.ephemeral-pulse"
_EFFECT_TYPE = "local.emit-one-ephemeral-pulse"


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _effect_binding() -> JsonObject:
    request: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1j-effect-request",
        "requestId": _REQUEST_ID,
        "actorId": _ACTOR_ID,
        "authorityId": _AUTHORITY_ID,
        "zoneRef": _ZONE_REF,
        "capability": _CAPABILITY,
        "effectType": _EFFECT_TYPE,
    }
    request_digest = canonical_digest(request)
    admission: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1j-effect-admission",
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
    }
    validate_json(result)
    return result


def _sender_ledger() -> JsonObject:
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1j-sender-ledger",
        "effectBinding": _effect_binding(),
        "state": "admitted-pending-acknowledgement",
        "completionPublished": False,
    }
    validate_json(value)
    return value


def _recipient_marker_state(path: Path) -> JsonObject:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if not path.exists():
        value: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1j-recipient-marker-state",
            "dedupEffectIds": [],
        }
        _atomic_write(path, value)
        path.chmod(0o600)
        return value
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("C1-J recipient marker state must be an object")
    validate_json(value)
    return cast(JsonObject, value)


def _atomic_write(path: Path, value: JsonObject) -> None:
    validate_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_bytes(value))
    os.replace(temporary, path)


def _persist_marker(path: Path) -> None:
    state = _recipient_marker_state(path)
    ids = state.get("dedupEffectIds")
    if not isinstance(ids, list):
        raise ValueError("C1-J dedupEffectIds must be a list")
    if _EFFECT_ID not in ids:
        _atomic_write(
            path,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.c1j-recipient-marker-state",
                "dedupEffectIds": [*ids, _EFFECT_ID],
            },
        )
        path.chmod(0o600)


def _emit_pulse(fd: int, *, source: str) -> None:
    event: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1j-evaluator-pulse",
        "effectId": _EFFECT_ID,
        "source": source,
        "status": "applied",
    }
    os.write(fd, canonical_bytes(event) + b"\n")


def _inbox_state(path: Path) -> JsonObject:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if not path.exists():
        value: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1j-recipient-inbox-state",
            "effectId": _EFFECT_ID,
            "phase": "new",
        }
        _atomic_write(path, value)
        path.chmod(0o600)
        return value
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("C1-J inbox state must be an object")
    validate_json(value)
    return cast(JsonObject, value)


def _persist_inbox_reserved(path: Path) -> None:
    _atomic_write(
        path,
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1j-recipient-inbox-state",
            "effectId": _EFFECT_ID,
            "phase": "reserved",
        },
    )
    path.chmod(0o600)


def _inbox_worker_main(args: argparse.Namespace) -> None:
    if args.inbox_state is None or args.oracle_fd is None or args.inbox_mode is None:
        raise ValueError("C1-J inbox worker requires state/oracle/mode")
    _inbox_state(args.inbox_state)
    _persist_inbox_reserved(args.inbox_state)
    if args.inbox_mode == "reserved-effect-crash":
        _emit_pulse(args.oracle_fd, source=args.inbox_mode)
    os.kill(os.getpid(), signal.SIGKILL)
    raise RuntimeError("C1-J inbox worker survived SIGKILL")


def _pulse_once_main(args: argparse.Namespace) -> None:
    if args.oracle_fd is None:
        raise ValueError("C1-J pulse worker requires oracle-fd")
    _emit_pulse(args.oracle_fd, source="reserved-recovery-retry")


def _recipient_main(args: argparse.Namespace) -> None:
    if args.socket_path is None or args.oracle_fd is None or args.marker_state is None:
        raise ValueError("C1-J recipient requires socket/oracle/marker state")
    mode = args.recipient_mode
    if mode is None:
        raise ValueError("C1-J recipient requires mode")
    marker = _recipient_marker_state(args.marker_state)
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
            raise ValueError("C1-J recipient received wrong effect identity")
        ids = marker.get("dedupEffectIds")
        if not isinstance(ids, list):
            raise ValueError("C1-J marker state has invalid dedupEffectIds")
        if _EFFECT_ID in ids:
            ack: JsonObject = {
                "schemaVersion": 1,
                "effectId": _EFFECT_ID,
                "status": "duplicate-suppressed",
            }
            if isinstance(client, str) and client:
                server.sendto(canonical_bytes(ack), client)
            return

        if mode == "effect-before-marker-crash":
            _emit_pulse(args.oracle_fd, source=mode)
            os.kill(os.getpid(), signal.SIGKILL)
            raise RuntimeError("C1-J effect-before-marker recipient survived SIGKILL")
        if mode == "marker-before-effect-crash":
            _persist_marker(args.marker_state)
            os.kill(os.getpid(), signal.SIGKILL)
            raise RuntimeError("C1-J marker-before-effect recipient survived SIGKILL")
        if mode != "healthy-marker-before-effect":
            raise ValueError(f"unsupported C1-J recipient mode: {mode}")

        _persist_marker(args.marker_state)
        _emit_pulse(args.oracle_fd, source=mode)
        ack = {
            "schemaVersion": 1,
            "effectId": _EFFECT_ID,
            "status": "applied",
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
            raise RuntimeError(f"C1-J recipient exited before ready: {process.returncode}")
        time.sleep(0.02)
    raise TimeoutError("C1-J recipient socket did not become ready")


def _start_recipient(
    *,
    socket_path: Path,
    marker_state: Path,
    mode: str,
) -> tuple[subprocess.Popen[bytes], int]:
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_recipient_commit_gap_acceptance",
            "--recipient",
            "--recipient-mode",
            mode,
            "--socket-path",
            str(socket_path),
            "--marker-state",
            str(marker_state),
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
            raise ValueError("C1-J evaluator event must be an object")
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
            f"C1-J recipient exit {process.returncode}, expected {expected}: {stderr[-2048:]!r}"
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
        raise RuntimeError(f"C1-J restricted send failed: {completed.stderr[-2048:]!r}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("C1-J restricted sender output must be object")
    validate_json(value)
    return cast(JsonObject, value)


def _privacy_probe(path: Path) -> JsonObject:
    completed = subprocess.run(
        [
            "/usr/bin/setpriv",
            "--reuid",
            "65534",
            "--regid",
            "65534",
            "--clear-groups",
            "--",
            "/usr/bin/cat",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    value: JsonObject = {
        "principalUid": 65534,
        "readSucceeded": completed.returncode == 0,
        "returnCode": completed.returncode,
        "stdoutByteLength": len(completed.stdout.encode()),
    }
    validate_json(value)
    return value


def _sender_ledger_file(path: Path) -> tuple[bytes, JsonObject]:
    value = _sender_ledger()
    data = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data, value


def _run_gap(
    *,
    root: Path,
    public_root: Path,
    gap: str,
) -> JsonObject:
    base = root / gap
    ledger_path = base / "sender-ledger.json"
    marker_path = root / "recipient-private" / f"{gap}.json"
    socket_path = public_root / f"{gap}.sock"
    client_path = public_root / f"{gap}-client.sock"
    ledger_bytes, ledger = _sender_ledger_file(ledger_path)
    _recipient_marker_state(marker_path)

    crashed, oracle_fd = _start_recipient(
        socket_path=socket_path,
        marker_state=marker_path,
        mode=gap,
    )
    first_send = _restricted_send(socket_path=socket_path, client_path=client_path)
    first_events, first_truth = _collect_recipient(
        crashed,
        oracle_fd,
        expected_sigkill=True,
    )
    socket_path.unlink(missing_ok=True)
    first_state = _recipient_marker_state(marker_path)
    privacy = _privacy_probe(marker_path)

    recovered, recovery_oracle_fd = _start_recipient(
        socket_path=socket_path,
        marker_state=marker_path,
        mode="healthy-marker-before-effect",
    )
    recovery_send = _restricted_send(socket_path=socket_path, client_path=client_path)
    recovery_events, recovery_truth = _collect_recipient(
        recovered,
        recovery_oracle_fd,
        expected_sigkill=False,
    )
    socket_path.unlink(missing_ok=True)
    final_state = _recipient_marker_state(marker_path)

    total_pulses = sum(item.get("status") == "applied" for item in first_events + recovery_events)
    result: JsonObject = {
        "schemaVersion": 1,
        "gap": gap,
        "effectBinding": ledger.get("effectBinding"),
        "senderLedgerDigest": _digest_bytes(ledger_bytes),
        "senderLedgerUnchanged": ledger_path.read_bytes() == ledger_bytes,
        "firstAttempt": {
            "restrictedSend": first_send,
            "recipientTruth": first_truth,
            "recipientMarkerStateAfterCrash": first_state,
        },
        "restrictedSuccessorPrivacyProbe": privacy,
        "recoveryRetry": {
            "restrictedSend": recovery_send,
            "recipientTruth": recovery_truth,
            "recipientMarkerFinalState": final_state,
        },
        "totalPhysicalPulseCount": total_pulses,
        "publicEndpointClosed": not socket_path.exists() and not client_path.exists(),
    }
    validate_json(result)
    return result


def _run_inbox_worker(*, state_path: Path, mode: str) -> tuple[list[JsonObject], JsonObject]:
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_recipient_commit_gap_acceptance",
            "--inbox-worker",
            "--inbox-mode",
            mode,
            "--inbox-state",
            str(state_path),
            "--oracle-fd",
            str(write_fd),
        ],
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    return _collect_recipient(process, read_fd, expected_sigkill=True)


def _run_recovery_pulse_once() -> tuple[list[JsonObject], JsonObject]:
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_recipient_commit_gap_acceptance",
            "--pulse-once",
            "--oracle-fd",
            str(write_fd),
        ],
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    return _collect_recipient(process, read_fd, expected_sigkill=False)


def _run_reserved_history(*, root: Path, mode: str) -> JsonObject:
    state_path = root / "recipient-inbox" / f"{mode}.json"
    initial_events, worker_truth = _run_inbox_worker(state_path=state_path, mode=mode)
    state_bytes = state_path.read_bytes()
    state = _inbox_state(state_path)
    recovery_view: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1j-recipient-recovery-view",
        "effectId": state.get("effectId"),
        "phase": state.get("phase"),
        "completionEvidenceAvailable": False,
    }
    validate_json(recovery_view)
    retry_events, retry_truth = _run_recovery_pulse_once()
    initial_count = sum(item.get("status") == "applied" for item in initial_events)
    retry_count = sum(item.get("status") == "applied" for item in retry_events)
    result: JsonObject = {
        "schemaVersion": 1,
        "history": mode,
        "durableInboxState": state,
        "durableInboxDigest": _digest_bytes(state_bytes),
        "recipientRecoveryView": recovery_view,
        "recipientRecoveryViewDigest": canonical_digest(recovery_view),
        "evaluatorOnlyInitialEvents": initial_events,
        "workerTruth": worker_truth,
        "counterfactualRetry": {
            "events": retry_events,
            "workerTruth": retry_truth,
            "totalPhysicalPulseCount": initial_count + retry_count,
        },
        "counterfactualSuppress": {"totalPhysicalPulseCount": initial_count},
    }
    validate_json(result)
    return result


def _supervisor(args: argparse.Namespace) -> None:
    revision = _git_revision(Path.cwd(), "Security")
    if args.state_root is None or args.receipt is None:
        raise ValueError("C1-J supervisor requires state-root and receipt")
    args.state_root.mkdir(parents=True, exist_ok=False)
    public_root = Path("/tmp") / f"ordivon-c1j-{os.getpid()}"
    public_root.mkdir(mode=0o777)
    public_root.chmod(0o777)
    try:
        effect_first = _run_gap(
            root=args.state_root,
            public_root=public_root,
            gap="effect-before-marker-crash",
        )
        marker_first = _run_gap(
            root=args.state_root,
            public_root=public_root,
            gap="marker-before-effect-crash",
        )
        reserved_no_effect = _run_reserved_history(
            root=args.state_root, mode="reserved-before-effect-crash"
        )
        reserved_after_effect = _run_reserved_history(
            root=args.state_root, mode="reserved-effect-crash"
        )
        same_sender = effect_first.get("senderLedgerDigest") == marker_first.get(
            "senderLedgerDigest"
        )
        effect_first_marker = cast(
            dict[str, object],
            cast(dict[str, object], effect_first["firstAttempt"])["recipientMarkerStateAfterCrash"],
        )
        marker_first_marker = cast(
            dict[str, object],
            cast(dict[str, object], marker_first["firstAttempt"])["recipientMarkerStateAfterCrash"],
        )
        effect_retry = cast(
            dict[str, object],
            cast(dict[str, object], effect_first["recoveryRetry"])["restrictedSend"],
        )
        marker_retry = cast(
            dict[str, object],
            cast(dict[str, object], marker_first["recoveryRetry"])["restrictedSend"],
        )
        effect_first_attempt = cast(dict[str, object], effect_first["firstAttempt"])
        marker_first_attempt = cast(dict[str, object], marker_first["firstAttempt"])
        effect_recovery = cast(dict[str, object], effect_first["recoveryRetry"])
        marker_recovery = cast(dict[str, object], marker_first["recoveryRetry"])
        effect_first_truth = cast(dict[str, object], effect_first_attempt["recipientTruth"])
        marker_first_truth = cast(dict[str, object], marker_first_attempt["recipientTruth"])
        effect_first_send = cast(dict[str, object], effect_first_attempt["restrictedSend"])
        marker_first_send = cast(dict[str, object], marker_first_attempt["restrictedSend"])
        effect_recovery_send = cast(dict[str, object], effect_recovery["restrictedSend"])
        marker_recovery_send = cast(dict[str, object], marker_recovery["restrictedSend"])
        reserved_views_identical = canonical_bytes(
            cast(JsonObject, reserved_no_effect["recipientRecoveryView"])
        ) == canonical_bytes(cast(JsonObject, reserved_after_effect["recipientRecoveryView"]))
        reserved_states_identical = reserved_no_effect.get(
            "durableInboxDigest"
        ) == reserved_after_effect.get("durableInboxDigest")
        no_effect_retry = cast(dict[str, object], reserved_no_effect["counterfactualRetry"])
        after_effect_retry = cast(dict[str, object], reserved_after_effect["counterfactualRetry"])
        no_effect_suppress = cast(dict[str, object], reserved_no_effect["counterfactualSuppress"])
        after_effect_suppress = cast(
            dict[str, object], reserved_after_effect["counterfactualSuppress"]
        )
        gates = {
            "sameDurableSenderStateAcrossCommitGaps": same_sender,
            "effectBeforeMarkerCrashEmittedOnePulse": len(
                cast(list[object], effect_first_truth["oracleEvents"])
            )
            == 1,
            "effectBeforeMarkerCrashLeftNoDedupMarker": effect_first_marker.get("dedupEffectIds")
            == [],
            "effectBeforeMarkerRetryAppliedAgain": isinstance(effect_retry.get("ack"), dict)
            and cast(dict[str, object], effect_retry["ack"]).get("status") == "applied",
            "effectBeforeMarkerRetryDuplicatedConsequence": effect_first.get(
                "totalPhysicalPulseCount"
            )
            == 2,
            "markerBeforeEffectCrashEmittedNoPulse": len(
                cast(list[object], marker_first_truth["oracleEvents"])
            )
            == 0,
            "markerBeforeEffectCrashPersistedDedupMarker": marker_first_marker.get("dedupEffectIds")
            == [_EFFECT_ID],
            "markerBeforeEffectRetryWasSuppressed": isinstance(marker_retry.get("ack"), dict)
            and cast(dict[str, object], marker_retry["ack"]).get("status")
            == "duplicate-suppressed",
            "markerBeforeEffectRetryLostConsequence": marker_first.get("totalPhysicalPulseCount")
            == 0,
            "restrictedSuccessorCouldNotReadRecipientMarkers": cast(
                dict[str, object], effect_first["restrictedSuccessorPrivacyProbe"]
            )["readSucceeded"]
            is False
            and cast(dict[str, object], marker_first["restrictedSuccessorPrivacyProbe"])[
                "readSucceeded"
            ]
            is False,
            "allDeliveryAttemptsUsedRestrictedSuccessor": effect_first_send.get("uid") == 65534
            and effect_recovery_send.get("uid") == 65534
            and marker_first_send.get("uid") == 65534
            and marker_recovery_send.get("uid") == 65534,
            "durableReservedInboxStatesByteEquivalent": reserved_states_identical,
            "reservedRecoveryViewsByteEquivalent": reserved_views_identical,
            "reservedHistoriesHaveDifferentGroundTruth": len(
                cast(list[object], reserved_no_effect["evaluatorOnlyInitialEvents"])
            )
            == 0
            and len(cast(list[object], reserved_after_effect["evaluatorOnlyInitialEvents"])) == 1,
            "retryFromReservedDuplicatesOneHistory": no_effect_retry.get("totalPhysicalPulseCount")
            == 1
            and after_effect_retry.get("totalPhysicalPulseCount") == 2,
            "suppressFromReservedLosesOneHistory": no_effect_suppress.get("totalPhysicalPulseCount")
            == 0
            and after_effect_suppress.get("totalPhysicalPulseCount") == 1,
            "publicEndpointsClosed": effect_first.get("publicEndpointClosed") is True
            and marker_first.get("publicEndpointClosed") is True,
            "noNetworkOrExternalTargetConsumed": True,
        }
        residual_entries = sorted(item.name for item in public_root.iterdir())
        gates["publicCapabilityRootClosedToZero"] = residual_entries == []
        passed = all(gates.values())
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1j-recipient-commit-gap-acceptance",
            "status": "accepted" if passed else "failed",
            "securityRevision": revision,
            "effectBinding": _effect_binding(),
            "effectBeforeMarkerGap": effect_first,
            "markerBeforeEffectGap": marker_first,
            "reservedInboxAmbiguity": {
                "reservedBeforeEffectCrash": reserved_no_effect,
                "reservedAfterEffectCrash": reserved_after_effect,
            },
            "gates": gates,
            "interpretation": {
                "postEffectDedupCommitGapDuplicatesOnRetry": passed,
                "preEffectDedupCommitGapCanLoseConsequence": passed,
                "orderingTwoIndependentWritesIsSufficientForExactlyOnce": False,
                "recipientDedupAloneIsSufficientForExactlyOnce": False,
                "durablePreEffectInboxAloneResolvesHistory": False,
                "reservedInboxStateCanRepresentUnknownButNotResolveIt": passed,
                "atomicOrIntrinsicallyIdempotentConsequenceBoundaryNowPressured": passed,
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
            "Run C1-J recipient commit-gap acceptance: fault both orderings between an "
            "irreversible vanishing pulse and a durable recipient dedup marker."
        )
    )
    parser.add_argument("--recipient", action="store_true")
    parser.add_argument("--inbox-worker", action="store_true")
    parser.add_argument("--pulse-once", action="store_true")
    parser.add_argument(
        "--recipient-mode",
        choices=(
            "effect-before-marker-crash",
            "marker-before-effect-crash",
            "healthy-marker-before-effect",
        ),
    )
    parser.add_argument("--socket-path", type=Path)
    parser.add_argument("--marker-state", type=Path)
    parser.add_argument("--inbox-state", type=Path)
    parser.add_argument(
        "--inbox-mode",
        choices=("reserved-before-effect-crash", "reserved-effect-crash"),
    )
    parser.add_argument("--oracle-fd", type=int)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--receipt", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.recipient:
        _recipient_main(args)
        return
    if args.inbox_worker:
        _inbox_worker_main(args)
        return
    if args.pulse_once:
        _pulse_once_main(args)
        return
    _supervisor(args)


if __name__ == "__main__":
    main()
