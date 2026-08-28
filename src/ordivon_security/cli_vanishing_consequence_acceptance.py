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

from ordivon_security._canonical import (
    JsonObject,
    canonical_bytes,
    canonical_digest,
    validate_json,
)
from ordivon_security.acceptance_support import git_revision, write_receipt

_EFFECT_ID = "range-effect:c1i-vanishing-pulse-v1"
_REQUEST_ID = "range-effect-request:c1i-vanishing-pulse-v1"
_AUTHORITY_ID = "range-authority:c1i-local-vanishing-consequence"
_ACTOR_ID = "actor:c1i-local-controller"
_ZONE_REF = "zone:c1i-local-no-uplink"
_CAPABILITY = "local.ephemeral-pulse"
_EFFECT_TYPE = "local.emit-one-ephemeral-pulse"


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _effect_binding() -> JsonObject:
    request: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1i-effect-request",
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
        "kind": "ordivon.security.c1i-effect-admission",
        "requestId": _REQUEST_ID,
        "requestDigest": request_digest,
        "authorityId": _AUTHORITY_ID,
        "admitted": True,
    }
    admission_digest = canonical_digest(admission)
    binding: JsonObject = {
        "actorId": _ACTOR_ID,
        "authorityId": _AUTHORITY_ID,
        "zoneRef": _ZONE_REF,
        "capability": _CAPABILITY,
        "effectType": _EFFECT_TYPE,
        "requestId": _REQUEST_ID,
        "requestDigest": request_digest,
        "admissionDigest": admission_digest,
        "effectId": _EFFECT_ID,
    }
    validate_json(binding)
    return binding


def _sender_ledger() -> JsonObject:
    ledger: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1i-sender-ledger",
        "effectBinding": _effect_binding(),
        "state": "admitted-pending-acknowledgement",
        "completionPublished": False,
        "recipientInternalStateAuthority": "recipient-private",
    }
    validate_json(ledger)
    return ledger


def _successor_view(ledger: JsonObject) -> JsonObject:
    binding = ledger.get("effectBinding")
    if not isinstance(binding, dict):
        raise ValueError("C1-I sender ledger lacks effect binding")
    view: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1i-successor-view",
        "effectId": binding.get("effectId"),
        "senderLedgerDigest": canonical_digest(ledger),
        "senderState": ledger.get("state"),
        "completionPublished": ledger.get("completionPublished"),
        "controllerAlive": False,
        "recipientProcessAlive": False,
        "recipientSocketPresent": False,
        "completionEvidenceAvailable": False,
        "recipientInternalStateVisible": False,
    }
    validate_json(view)
    return view


def classify_successor_view(view: JsonObject) -> JsonObject:
    if view.get("completionPublished") is True:
        status = "completed"
        reason = "durable-completion-published"
        blind_resend = False
        publish = False
    elif view.get("completionEvidenceAvailable") is True:
        status = "reobserve-required"
        reason = "independent-completion-evidence-available"
        blind_resend = False
        publish = False
    else:
        status = "unknown"
        reason = "delivery-history-not-observable"
        blind_resend = False
        publish = False
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1i-recovery-classification",
        "status": status,
        "reason": reason,
        "blindResendAuthorized": blind_resend,
        "completionPublicationAuthorized": publish,
    }
    validate_json(result)
    return result


def _atomic_write_json(path: Path, value: JsonObject) -> None:
    validate_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_bytes(value) + b"\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _recipient_state(path: Path) -> JsonObject:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if not path.exists():
        state: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1i-recipient-idempotency-state",
            "appliedEffectIds": [],
            "applicationCount": 0,
        }
        _atomic_write_json(path, state)
        path.chmod(0o600)
        return state
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("C1-I recipient state must be an object")
    validate_json(value)
    return cast(JsonObject, value)


def _recipient_main(args: argparse.Namespace) -> None:
    socket_path = args.socket_path
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    if len(os.fsencode(socket_path)) >= 100:
        raise ValueError("C1-I Unix socket path is too long")
    dedup_path = args.dedup_state
    if dedup_path is not None:
        _recipient_state(dedup_path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    pulse_count = 0
    try:
        server.bind(str(socket_path))
        socket_path.chmod(0o777)
        while True:
            payload, client = server.recvfrom(65536)
            message = json.loads(payload)
            if not isinstance(message, dict) or message.get("effectId") != _EFFECT_ID:
                ack: JsonObject = {
                    "schemaVersion": 1,
                    "effectId": _EFFECT_ID,
                    "status": "rejected",
                }
            elif dedup_path is None:
                pulse_count += 1
                event: JsonObject = {
                    "schemaVersion": 1,
                    "effectId": _EFFECT_ID,
                    "status": "applied",
                    "pulseOrdinal": pulse_count,
                }
                os.write(args.oracle_fd, canonical_bytes(event) + b"\n")
                ack = {
                    "schemaVersion": 1,
                    "effectId": _EFFECT_ID,
                    "status": "applied",
                }
            else:
                state = _recipient_state(dedup_path)
                applied = state.get("appliedEffectIds")
                count = state.get("applicationCount")
                if not isinstance(applied, list) or not isinstance(count, int):
                    raise ValueError("C1-I recipient state shape is invalid")
                if _EFFECT_ID in applied:
                    event = {
                        "schemaVersion": 1,
                        "effectId": _EFFECT_ID,
                        "status": "duplicate-suppressed",
                        "applicationCount": count,
                    }
                    os.write(args.oracle_fd, canonical_bytes(event) + b"\n")
                    ack = {
                        "schemaVersion": 1,
                        "effectId": _EFFECT_ID,
                        "status": "duplicate-suppressed",
                    }
                else:
                    new_state: JsonObject = {
                        "schemaVersion": 1,
                        "kind": "ordivon.security.c1i-recipient-idempotency-state",
                        "appliedEffectIds": [*applied, _EFFECT_ID],
                        "applicationCount": count + 1,
                    }
                    _atomic_write_json(dedup_path, new_state)
                    event = {
                        "schemaVersion": 1,
                        "effectId": _EFFECT_ID,
                        "status": "applied",
                        "applicationCount": count + 1,
                    }
                    os.write(args.oracle_fd, canonical_bytes(event) + b"\n")
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


def _controller_main(args: argparse.Namespace) -> None:
    if args.controller_history == "undelivered":
        print(json.dumps({"stage": "before-send"}, sort_keys=True), flush=True)
        os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError("C1-I undelivered controller survived SIGKILL")
    client_path = args.client_path
    client_path.parent.mkdir(parents=True, exist_ok=True)
    client_path.unlink(missing_ok=True)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        client.bind(str(client_path))
        client.settimeout(10)
        message: JsonObject = {"schemaVersion": 1, "effectId": _EFFECT_ID}
        client.sendto(canonical_bytes(message), str(args.socket_path))
        ack_bytes, _ = client.recvfrom(65536)
        ack = json.loads(ack_bytes)
        print(
            json.dumps({"stage": "ack-received-not-published", "ack": ack}, sort_keys=True),
            flush=True,
        )
        os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError("C1-I delivered controller survived SIGKILL")
    finally:
        client.close()
        client_path.unlink(missing_ok=True)


def _wait_socket(
    path: Path, process: subprocess.Popen[bytes], timeout_seconds: float = 10.0
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.exists() and process.poll() is None:
            return
        if process.poll() is not None:
            raise RuntimeError(f"C1-I recipient exited before ready: {process.returncode}")
        time.sleep(0.02)
    raise TimeoutError("C1-I recipient socket did not become ready")


def _start_recipient(
    *,
    socket_path: Path,
    dedup_state: Path | None,
) -> tuple[subprocess.Popen[bytes], int]:
    read_fd, write_fd = os.pipe()
    command = [
        sys.executable,
        "-m",
        "ordivon_security.cli_vanishing_consequence_acceptance",
        "--recipient",
        "--socket-path",
        str(socket_path),
        "--oracle-fd",
        str(write_fd),
    ]
    if dedup_state is not None:
        command += ["--dedup-state", str(dedup_state)]
    process = subprocess.Popen(
        command,
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    _wait_socket(socket_path, process)
    return process, read_fd


def _stop_recipient(
    process: subprocess.Popen[bytes], read_fd: int, socket_path: Path
) -> list[JsonObject]:
    if process.poll() is None:
        process.terminate()
    try:
        _, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        _, stderr = process.communicate(timeout=10)
    if process.returncode not in {-signal.SIGTERM, 0}:
        raise RuntimeError(f"C1-I recipient failed: {process.returncode}: {stderr[-2048:]!r}")
    chunks: list[bytes] = []
    while True:
        chunk = os.read(read_fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(read_fd)
    socket_path.unlink(missing_ok=True)
    events: list[JsonObject] = []
    for line in b"".join(chunks).splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("C1-I oracle event must be an object")
        validate_json(value)
        events.append(cast(JsonObject, value))
    return events


def _run_crashing_controller(
    *,
    history: str,
    socket_path: Path,
    client_path: Path,
) -> JsonObject:
    command = [
        sys.executable,
        "-m",
        "ordivon_security.cli_vanishing_consequence_acceptance",
        "--controller",
        "--controller-history",
        history,
        "--socket-path",
        str(socket_path),
        "--client-path",
        str(client_path),
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate(timeout=15)
    if process.returncode != -signal.SIGKILL:
        detail = stderr[-2048:]
        raise RuntimeError(
            f"C1-I {history} controller did not die by SIGKILL: {process.returncode}: {detail!r}"
        )
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"C1-I {history} controller emitted unexpected evidence: {lines}")
    evidence = json.loads(lines[0])
    if not isinstance(evidence, dict):
        raise ValueError("C1-I controller evidence must be an object")
    validate_json(evidence)
    client_path.unlink(missing_ok=True)
    return cast(JsonObject, evidence)


def _send_effect_once_unprivileged(*, socket_path: Path, client_path: Path) -> JsonObject:
    script = r"""
import json
import os
import socket
import sys
socket_path, client_path, effect_id = sys.argv[1:4]
try:
    os.unlink(client_path)
except FileNotFoundError:
    pass
client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
try:
    client.bind(client_path)
    client.settimeout(10)
    payload = json.dumps(
        {"schemaVersion": 1, "effectId": effect_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    client.sendto(payload, socket_path)
    ack_bytes, _ = client.recvfrom(65536)
    print(json.dumps({"uid": os.geteuid(), "ack": json.loads(ack_bytes)}, sort_keys=True))
finally:
    client.close()
    try:
        os.unlink(client_path)
    except FileNotFoundError:
        pass
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
        timeout=15,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "C1-I restricted successor resend failed: "
            f"{completed.returncode}: {completed.stderr[-2048:]!r}"
        )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("C1-I restricted successor result must be an object")
    validate_json(value)
    return cast(JsonObject, value)


def _recipient_privacy_probe(path: Path) -> JsonObject:
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
        timeout=10,
    )
    result: JsonObject = {
        "principalUid": 65534,
        "readSucceeded": completed.returncode == 0,
        "returnCode": completed.returncode,
        "stdoutByteLength": len(completed.stdout.encode()),
        "stderrPresent": bool(completed.stderr),
    }
    validate_json(result)
    return result


def _history_paths(
    root: Path,
    public_socket_root: Path,
    phase: str,
    history: str,
) -> tuple[Path, Path, Path, Path]:
    base = root / phase / history
    return (
        base / "sender-ledger.json",
        public_socket_root / f"{phase}-{history}.sock",
        public_socket_root / f"{phase}-{history}-client.sock",
        root / "recipient-private" / f"{phase}-{history}.json",
    )


def _prepare_sender_ledger(path: Path) -> tuple[bytes, JsonObject, JsonObject]:
    ledger = _sender_ledger()
    data = canonical_bytes(ledger)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    view = _successor_view(ledger)
    return data, ledger, view


def _run_baseline_history(root: Path, public_socket_root: Path, history: str) -> JsonObject:
    ledger_path, socket_path, client_path, _ = _history_paths(
        root, public_socket_root, "baseline", history
    )
    ledger_bytes, ledger, _ = _prepare_sender_ledger(ledger_path)
    recipient, oracle_fd = _start_recipient(socket_path=socket_path, dedup_state=None)
    controller_evidence = _run_crashing_controller(
        history=history,
        socket_path=socket_path,
        client_path=client_path,
    )
    initial_oracle = _stop_recipient(recipient, oracle_fd, socket_path)
    if socket_path.exists() or client_path.exists():
        raise RuntimeError("C1-I baseline left transient sockets before recovery observation")
    post_crash_value = json.loads(ledger_path.read_bytes())
    if not isinstance(post_crash_value, dict):
        raise ValueError("C1-I baseline durable ledger must remain an object")
    view = _successor_view(cast(JsonObject, post_crash_value))
    classification = classify_successor_view(view)

    replay_recipient, replay_oracle_fd = _start_recipient(socket_path=socket_path, dedup_state=None)
    replay_result = _send_effect_once_unprivileged(socket_path=socket_path, client_path=client_path)
    replay_ack = replay_result.get("ack")
    if not isinstance(replay_ack, dict):
        raise RuntimeError("C1-I baseline restricted resend lacks acknowledgement")
    replay_oracle = _stop_recipient(replay_recipient, replay_oracle_fd, socket_path)

    initial_applied = sum(event.get("status") == "applied" for event in initial_oracle)
    replay_applied = sum(event.get("status") == "applied" for event in replay_oracle)
    result: JsonObject = {
        "schemaVersion": 1,
        "history": history,
        "senderLedgerDigest": _sha256_bytes(ledger_bytes),
        "successorView": view,
        "successorViewDigest": canonical_digest(view),
        "classification": classification,
        "controllerEvidence": controller_evidence,
        "evaluatorOnlyInitialOracle": initial_oracle,
        "counterfactualBlindReplay": {
            "ack": replay_ack,
            "restrictedSuccessorUid": replay_result.get("uid"),
            "evaluatorOnlyReplayOracle": replay_oracle,
            "initialAppliedCount": initial_applied,
            "replayAppliedCount": replay_applied,
            "totalPhysicalApplications": initial_applied + replay_applied,
        },
        "senderLedgerUnchanged": ledger_path.read_bytes() == ledger_bytes,
        "transientWorldClosedBeforeClassification": not socket_path.exists()
        and not client_path.exists(),
        "recipientInternalStateVisibleToSuccessor": False,
        "effectBinding": ledger.get("effectBinding"),
    }
    validate_json(result)
    return result


def _run_idempotent_history(root: Path, public_socket_root: Path, history: str) -> JsonObject:
    ledger_path, socket_path, client_path, dedup_path = _history_paths(
        root, public_socket_root, "recipient-idempotency", history
    )
    ledger_bytes, ledger, _ = _prepare_sender_ledger(ledger_path)
    _recipient_state(dedup_path)
    recipient, oracle_fd = _start_recipient(socket_path=socket_path, dedup_state=dedup_path)
    controller_evidence = _run_crashing_controller(
        history=history,
        socket_path=socket_path,
        client_path=client_path,
    )
    initial_oracle = _stop_recipient(recipient, oracle_fd, socket_path)
    state_after_crash = _recipient_state(dedup_path)
    privacy_probe = _recipient_privacy_probe(dedup_path)
    post_crash_value = json.loads(ledger_path.read_bytes())
    if not isinstance(post_crash_value, dict):
        raise ValueError("C1-I idempotent durable ledger must remain an object")
    view = _successor_view(cast(JsonObject, post_crash_value))
    classification = classify_successor_view(view)

    recovery_recipient, recovery_oracle_fd = _start_recipient(
        socket_path=socket_path,
        dedup_state=dedup_path,
    )
    recovery_result = _send_effect_once_unprivileged(
        socket_path=socket_path, client_path=client_path
    )
    recovery_ack = recovery_result.get("ack")
    if not isinstance(recovery_ack, dict):
        raise RuntimeError("C1-I idempotent restricted resend lacks acknowledgement")
    recovery_oracle = _stop_recipient(
        recovery_recipient,
        recovery_oracle_fd,
        socket_path,
    )
    final_state = _recipient_state(dedup_path)
    completion: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1i-sender-completion",
        "effectId": _EFFECT_ID,
        "status": "completed-after-idempotent-resend",
        "acknowledged": recovery_ack.get("status") in {"applied", "duplicate-suppressed"},
    }
    result: JsonObject = {
        "schemaVersion": 1,
        "history": history,
        "senderLedgerDigest": _sha256_bytes(ledger_bytes),
        "successorView": view,
        "successorViewDigest": canonical_digest(view),
        "classificationBeforeResend": classification,
        "controllerEvidence": controller_evidence,
        "evaluatorOnlyInitialOracle": initial_oracle,
        "recipientPrivateStateAfterCrash": state_after_crash,
        "restrictedSuccessorPrivacyProbe": privacy_probe,
        "recoveryResend": {
            "ack": recovery_ack,
            "restrictedSuccessorUid": recovery_result.get("uid"),
            "evaluatorOnlyOracle": recovery_oracle,
        },
        "recipientPrivateFinalState": final_state,
        "completion": completion,
        "senderLedgerUnchangedBeforeCompletion": ledger_path.read_bytes() == ledger_bytes,
        "recipientInternalStateVisibleToSuccessor": False,
        "effectBinding": ledger.get("effectBinding"),
    }
    validate_json(result)
    return result


def _supervisor(args: argparse.Namespace) -> None:
    revision = git_revision(Path.cwd(), "Security")
    args.state_root.mkdir(parents=True, exist_ok=False)
    public_socket_root = Path("/tmp") / f"ordivon-c1i-{os.getpid()}"
    public_socket_root.mkdir(mode=0o777)
    public_socket_root.chmod(0o777)

    baseline = {
        history: _run_baseline_history(args.state_root, public_socket_root, history)
        for history in ("delivered", "undelivered")
    }
    baseline_delivered = cast(JsonObject, baseline["delivered"])
    baseline_undelivered = cast(JsonObject, baseline["undelivered"])
    baseline_views_identical = canonical_bytes(
        cast(JsonObject, baseline_delivered["successorView"])
    ) == canonical_bytes(cast(JsonObject, baseline_undelivered["successorView"]))
    baseline_ledgers_identical = baseline_delivered.get(
        "senderLedgerDigest"
    ) == baseline_undelivered.get("senderLedgerDigest")
    delivered_total = cast(dict[str, object], baseline_delivered["counterfactualBlindReplay"])[
        "totalPhysicalApplications"
    ]
    undelivered_total = cast(dict[str, object], baseline_undelivered["counterfactualBlindReplay"])[
        "totalPhysicalApplications"
    ]

    idempotent = {
        history: _run_idempotent_history(args.state_root, public_socket_root, history)
        for history in ("delivered", "undelivered")
    }
    idem_delivered = cast(JsonObject, idempotent["delivered"])
    idem_undelivered = cast(JsonObject, idempotent["undelivered"])
    idem_views_identical = canonical_bytes(
        cast(JsonObject, idem_delivered["successorView"])
    ) == canonical_bytes(cast(JsonObject, idem_undelivered["successorView"]))
    idem_ledgers_identical = idem_delivered.get("senderLedgerDigest") == idem_undelivered.get(
        "senderLedgerDigest"
    )
    delivered_final_state = cast(JsonObject, idem_delivered["recipientPrivateFinalState"])
    undelivered_final_state = cast(JsonObject, idem_undelivered["recipientPrivateFinalState"])
    delivered_ack = cast(dict[str, object], idem_delivered["recoveryResend"])["ack"]
    undelivered_ack = cast(dict[str, object], idem_undelivered["recoveryResend"])["ack"]

    gates = {
        "baselineSenderLedgersByteEquivalent": baseline_ledgers_identical,
        "baselineSuccessorViewsByteEquivalent": baseline_views_identical,
        "baselineDeliveredHistoryPhysicallyAppliedOnceBeforeCrash": len(
            cast(list[object], baseline_delivered["evaluatorOnlyInitialOracle"])
        )
        == 1,
        "baselineUndeliveredHistoryPhysicallyAppliedZeroBeforeCrash": len(
            cast(list[object], baseline_undelivered["evaluatorOnlyInitialOracle"])
        )
        == 0,
        "baselineBothClassifyUnknown": cast(
            dict[str, object], baseline_delivered["classification"]
        )["status"]
        == "unknown"
        and cast(dict[str, object], baseline_undelivered["classification"])["status"] == "unknown",
        "baselineUnknownRefusesBlindResend": cast(
            dict[str, object], baseline_delivered["classification"]
        )["blindResendAuthorized"]
        is False
        and cast(dict[str, object], baseline_undelivered["classification"])["blindResendAuthorized"]
        is False,
        "counterfactualBlindResendDuplicatesDeliveredHistory": delivered_total == 2,
        "counterfactualBlindResendAppliesUndeliveredHistoryOnce": undelivered_total == 1,
        "counterfactualBlindResendUsedRestrictedSuccessor": cast(
            dict[str, object], baseline_delivered["counterfactualBlindReplay"]
        )["restrictedSuccessorUid"]
        == 65534
        and cast(dict[str, object], baseline_undelivered["counterfactualBlindReplay"])[
            "restrictedSuccessorUid"
        ]
        == 65534,
        "recipientIdempotencyPrivateStateUnreadableByRestrictedSuccessor": cast(
            dict[str, object], idem_delivered["restrictedSuccessorPrivacyProbe"]
        )["readSucceeded"]
        is False
        and cast(dict[str, object], idem_undelivered["restrictedSuccessorPrivacyProbe"])[
            "readSucceeded"
        ]
        is False,
        "recipientIdempotencySenderViewsRemainEquivalent": idem_views_identical
        and idem_ledgers_identical,
        "recipientIdempotencyDeliveredRetrySuppressed": isinstance(delivered_ack, dict)
        and delivered_ack.get("status") == "duplicate-suppressed",
        "recipientIdempotencyUndeliveredRetryApplied": isinstance(undelivered_ack, dict)
        and undelivered_ack.get("status") == "applied",
        "recipientIdempotencyRetryUsedRestrictedSuccessor": cast(
            dict[str, object], idem_delivered["recoveryResend"]
        )["restrictedSuccessorUid"]
        == 65534
        and cast(dict[str, object], idem_undelivered["recoveryResend"])["restrictedSuccessorUid"]
        == 65534,
        "recipientIdempotencyConvergesBothToOneApplication": delivered_final_state.get(
            "applicationCount"
        )
        == 1
        and undelivered_final_state.get("applicationCount") == 1
        and delivered_final_state.get("appliedEffectIds") == [_EFFECT_ID]
        and undelivered_final_state.get("appliedEffectIds") == [_EFFECT_ID],
        "recoveryAckAllowsBothHistoriesToPublishCompletion": cast(
            dict[str, object], idem_delivered["completion"]
        )["acknowledged"]
        is True
        and cast(dict[str, object], idem_undelivered["completion"])["acknowledged"] is True,
        "noNetworkOrExternalTargetConsumed": True,
    }
    residual_public_entries = sorted(path.name for path in public_socket_root.iterdir())
    if not residual_public_entries:
        public_socket_root.rmdir()
    gates["publicDeliveryEndpointClosedToZero"] = not residual_public_entries
    passed = all(gates.values())
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1i-information-loss-acceptance",
        "status": "accepted" if passed else "failed",
        "securityRevision": revision,
        "effectBinding": _effect_binding(),
        "baseline": baseline,
        "recipientIdempotency": idempotent,
        "gates": gates,
        "interpretation": {
            "informationLossCanForceUnknown": passed,
            "sameSenderViewCannotRevealWhichHistoryOccurred": baseline_views_identical,
            "blindResendSafeWithoutRecipientDedup": False,
            "senderCompletionReceiptRequiredByBaseline": False,
            "recipientSideDurableEffectIdentitySufficesForSafeRetryInThisFaultModel": passed,
            "genericExactlyOnceFrameworkRequired": False,
            "genericCausalDagRequired": False,
        },
    }
    write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if not passed:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run C1-I information-loss acceptance over an isolated local one-shot consequence: "
            "compare byte-equivalent successor views from delivered and undelivered histories, "
            "then test recipient-side durable effect identity as the minimum safe-retry candidate."
        )
    )
    parser.add_argument("--recipient", action="store_true")
    parser.add_argument("--controller", action="store_true")
    parser.add_argument("--socket-path", type=Path)
    parser.add_argument("--client-path", type=Path)
    parser.add_argument("--oracle-fd", type=int)
    parser.add_argument("--dedup-state", type=Path)
    parser.add_argument("--controller-history", choices=("delivered", "undelivered"))
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--receipt", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.recipient:
        if args.socket_path is None or args.oracle_fd is None:
            raise ValueError("C1-I recipient requires socket-path and oracle-fd")
        _recipient_main(args)
        return
    if args.controller:
        if args.socket_path is None or args.client_path is None or args.controller_history is None:
            raise ValueError("C1-I controller requires history/socket/client")
        _controller_main(args)
        return
    if args.state_root is None or args.receipt is None:
        raise ValueError("C1-I supervisor requires state-root and receipt")
    _supervisor(args)


if __name__ == "__main__":
    main()
