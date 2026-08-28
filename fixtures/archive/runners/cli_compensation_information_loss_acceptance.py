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
from ordivon_security.acceptance_support import git_revision, write_receipt

_ORIGINAL_EFFECT_ID = "range-effect:c1m-private-increment-v1"
_NAIVE_COMPENSATION_EFFECT_ID = "range-effect:c1m-naive-private-compensation-v1"
_IDEMPOTENT_COMPENSATION_EFFECT_ID = "range-effect:c1m-idempotent-private-compensation-v1"
_NAIVE_REQUEST_ID = "range-effect-request:c1m-naive-private-compensation-v1"
_IDEMPOTENT_REQUEST_ID = "range-effect-request:c1m-idempotent-private-compensation-v1"
_AUTHORITY_ID = "range-authority:c1m-private-compensation"
_ACTOR_ID = "actor:c1m-recovery-sender"
_ZONE_REF = "zone:c1m-local-no-uplink"
_NAIVE_CAPABILITY = "private-counter.subtract-one"
_NAIVE_EFFECT_TYPE = "private-counter.subtract-one"
_IDEMPOTENT_CAPABILITY = "private-counter.ensure-repaired"
_IDEMPOTENT_EFFECT_TYPE = "private-counter.ensure-repaired"
_INITIAL_BALANCE = 0
_DESIRED_BALANCE = 1
_DUPLICATE_BALANCE = 2


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _protocol_identity(action: str) -> tuple[str, str, str, str, str]:
    if action == "naive":
        return (
            _NAIVE_REQUEST_ID,
            _NAIVE_COMPENSATION_EFFECT_ID,
            _NAIVE_CAPABILITY,
            _NAIVE_EFFECT_TYPE,
            "non-idempotent-subtract-one",
        )
    if action == "idempotent":
        return (
            _IDEMPOTENT_REQUEST_ID,
            _IDEMPOTENT_COMPENSATION_EFFECT_ID,
            _IDEMPOTENT_CAPABILITY,
            _IDEMPOTENT_EFFECT_TYPE,
            "convergent-repair-duplicate",
        )
    raise ValueError(f"unsupported C1-M compensation protocol: {action}")


def _compensation_binding(action: str) -> JsonObject:
    request_id, effect_id, capability, effect_type, retry_semantics = _protocol_identity(action)
    request: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1m-compensation-request",
        "requestId": request_id,
        "actorId": _ACTOR_ID,
        "authorityId": _AUTHORITY_ID,
        "zoneRef": _ZONE_REF,
        "capability": capability,
        "effectType": effect_type,
        "compensatesEffectId": _ORIGINAL_EFFECT_ID,
        "duplicateBalance": _DUPLICATE_BALANCE,
        "desiredBalance": _DESIRED_BALANCE,
        "retrySemantics": retry_semantics,
    }
    request_digest = canonical_digest(request)
    admission: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1m-compensation-admission",
        "requestId": request_id,
        "requestDigest": request_digest,
        "authorityId": _AUTHORITY_ID,
        "admitted": True,
    }
    result: JsonObject = {
        "actorId": _ACTOR_ID,
        "authorityId": _AUTHORITY_ID,
        "zoneRef": _ZONE_REF,
        "capability": capability,
        "effectType": effect_type,
        "requestId": request_id,
        "requestDigest": request_digest,
        "admissionDigest": canonical_digest(admission),
        "compensationEffectId": effect_id,
        "compensatesEffectId": _ORIGINAL_EFFECT_ID,
        "duplicateBalance": _DUPLICATE_BALANCE,
        "desiredBalance": _DESIRED_BALANCE,
        "retrySemantics": retry_semantics,
    }
    validate_json(result)
    return result


def _sender_ledger(action: str) -> JsonObject:
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1m-sender-ledger",
        "compensationBinding": _compensation_binding(action),
        "state": "compensation-admitted-pending-acknowledgement",
        "completionPublished": False,
    }
    validate_json(value)
    return value


def _atomic_write(path: Path, value: JsonObject) -> None:
    validate_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_bytes(value))
    os.replace(temporary, path)


def _private_balance_path(root: Path) -> Path:
    return root / "balance.json"


def _private_world_inventory(root: Path) -> list[str]:
    if not root.exists():
        return []
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    )


def _initialize_private_world(root: Path) -> JsonObject:
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    _atomic_write(
        _private_balance_path(root),
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1m-private-balance",
            "balance": _INITIAL_BALANCE,
        },
    )
    _private_balance_path(root).chmod(0o600)
    setup: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1m-duplicate-setup",
        "before": _INITIAL_BALANCE,
        "afterFirstOriginal": _apply_original_private(root),
        "afterSecondOriginal": _apply_original_private(root),
    }
    validate_json(setup)
    return setup


def _read_private_balance(root: Path) -> int:
    value = json.loads(_private_balance_path(root).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("balance"), int):
        raise ValueError("C1-M private balance has invalid shape")
    return cast(int, value["balance"])


def _set_private_balance(root: Path, balance: int) -> None:
    _atomic_write(
        _private_balance_path(root),
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1m-private-balance",
            "balance": balance,
        },
    )
    _private_balance_path(root).chmod(0o600)


def _apply_original_private(root: Path) -> int:
    next_balance = _read_private_balance(root) + 1
    _set_private_balance(root, next_balance)
    return next_balance


def apply_naive_private_compensation(root: Path) -> JsonObject:
    before = _read_private_balance(root)
    if before <= 0:
        status_value = "conflict"
        mutated = False
        after = before
    else:
        after = before - 1
        _set_private_balance(root, after)
        status_value = "applied"
        mutated = True
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1m-naive-compensation-result",
        "compensationEffectId": _NAIVE_COMPENSATION_EFFECT_ID,
        "status": status_value,
        "worldMutated": mutated,
        "privateBalanceBefore": before,
        "privateBalanceAfter": after,
    }
    validate_json(result)
    return result


def apply_idempotent_private_compensation(root: Path) -> JsonObject:
    before = _read_private_balance(root)
    if before == _DUPLICATE_BALANCE:
        _set_private_balance(root, _DESIRED_BALANCE)
        after = _DESIRED_BALANCE
        status_value = "applied"
        mutated = True
    elif before == _DESIRED_BALANCE:
        after = before
        status_value = "already-repaired"
        mutated = False
    else:
        after = before
        status_value = "conflict"
        mutated = False
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1m-idempotent-compensation-result",
        "compensationEffectId": _IDEMPOTENT_COMPENSATION_EFFECT_ID,
        "status": status_value,
        "worldMutated": mutated,
        "privateBalanceBefore": before,
        "privateBalanceAfter": after,
    }
    validate_json(result)
    return result


def _successor_view(ledger: JsonObject) -> JsonObject:
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1m-successor-view",
        "compensationBinding": ledger.get("compensationBinding"),
        "senderState": ledger.get("state"),
        "completionPublished": ledger.get("completionPublished"),
        "controllerAlive": False,
        "recipientProcessAlive": False,
        "recipientSocketPresent": False,
        "compensationEvidenceAvailable": False,
        "recipientPrivateStateVisible": False,
    }
    validate_json(value)
    return value


def classify_successor_view(view: JsonObject) -> JsonObject:
    if (
        view.get("completionPublished") is False
        and view.get("controllerAlive") is False
        and view.get("recipientProcessAlive") is False
        and view.get("recipientSocketPresent") is False
        and view.get("compensationEvidenceAvailable") is False
        and view.get("recipientPrivateStateVisible") is False
    ):
        status_value = "unknown"
        blind_compensation = False
        completion_publication = False
        reason = "compensation-history-not-observable"
    else:
        status_value = "unsupported-view"
        blind_compensation = False
        completion_publication = False
        reason = "outside-c1m-baseline"
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1m-recovery-classification",
        "status": status_value,
        "reason": reason,
        "blindCompensationAuthorized": blind_compensation,
        "completionPublicationAuthorized": completion_publication,
    }
    validate_json(result)
    return result


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
    result: JsonObject = {
        "principalUid": 65534,
        "readSucceeded": completed.returncode == 0,
        "returnCode": completed.returncode,
        "stdoutByteLength": len(completed.stdout.encode()),
        "stderrPresent": bool(completed.stderr),
    }
    validate_json(result)
    return result


def _emit_oracle(fd: int, event: JsonObject) -> None:
    validate_json(event)
    os.write(fd, canonical_bytes(event) + b"\n")


def _recipient_main(args: argparse.Namespace) -> None:
    if args.socket_path is None or args.private_root is None or args.oracle_fd is None:
        raise ValueError("C1-M recipient requires socket/private-root/oracle")
    if args.action is None or args.mode is None:
        raise ValueError("C1-M recipient requires action/mode")
    socket_path = args.socket_path
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        server.bind(str(socket_path))
        socket_path.chmod(0o777)
        payload, client = server.recvfrom(65536)
        message = json.loads(payload)
        _, effect_id, _, _, _ = _protocol_identity(args.action)
        if not isinstance(message, dict) or message.get("effectId") != effect_id:
            raise ValueError("C1-M recipient received wrong compensation identity")
        _emit_oracle(
            args.oracle_fd,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.c1m-invocation",
                "stage": "received",
                "action": args.action,
                "mode": args.mode,
                "effectId": effect_id,
            },
        )
        if args.mode == "crash-before-apply":
            os.kill(os.getpid(), signal.SIGKILL)
            raise RuntimeError("C1-M pre-apply recipient survived SIGKILL")
        if args.action == "naive":
            result = apply_naive_private_compensation(args.private_root)
        elif args.action == "idempotent":
            result = apply_idempotent_private_compensation(args.private_root)
        else:
            raise ValueError(f"unsupported C1-M action: {args.action}")
        _emit_oracle(
            args.oracle_fd,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.c1m-invocation",
                "stage": "compensation-returned",
                "action": args.action,
                "mode": args.mode,
                "effectId": effect_id,
                "status": result.get("status"),
                "worldMutated": result.get("worldMutated"),
                "evaluatorOnlyPrivateBalanceAfter": result.get("privateBalanceAfter"),
            },
        )
        if args.mode == "apply-crash-before-ack":
            os.kill(os.getpid(), signal.SIGKILL)
            raise RuntimeError("C1-M post-apply recipient survived SIGKILL")
        ack: JsonObject = {
            "schemaVersion": 1,
            "effectId": effect_id,
            "status": result.get("status"),
            "semanticRepairSatisfied": result.get("privateBalanceAfter") == _DESIRED_BALANCE,
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
            raise RuntimeError(f"C1-M recipient exited before ready: {process.returncode}")
        time.sleep(0.02)
    raise TimeoutError("C1-M recipient socket did not become ready")


def _start_recipient(
    *, socket_path: Path, private_root: Path, action: str, mode: str
) -> tuple[subprocess.Popen[bytes], int]:
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_compensation_information_loss_acceptance",
            "--recipient",
            "--action",
            action,
            "--mode",
            mode,
            "--socket-path",
            str(socket_path),
            "--private-root",
            str(private_root),
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
            raise ValueError("C1-M oracle event must be object")
        validate_json(item)
        events.append(cast(JsonObject, item))
    return events


def _collect(
    process: subprocess.Popen[bytes], read_fd: int, *, expected_sigkill: bool
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
            f"C1-M recipient exit {process.returncode}, expected {expected}: {stderr[-2048:]!r}"
        )
    truth: JsonObject = {
        "returnCode": process.returncode,
        "stdoutByteLength": len(stdout),
        "stderrByteLength": len(stderr),
        "oracleEvents": events,
    }
    validate_json(truth)
    return events, truth


def _restricted_send(*, socket_path: Path, client_path: Path, effect_id: str) -> JsonObject:
    script = r"""
import json, os, socket, sys
socket_path, client_path, effect_id = sys.argv[1:4]
try: os.unlink(client_path)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
try:
    s.bind(client_path); s.settimeout(3)
    payload=json.dumps({"schemaVersion":1,"effectId":effect_id},sort_keys=True,separators=(",",":")).encode()
    s.sendto(payload,socket_path)
    try:
        data,_=s.recvfrom(65536); ack=json.loads(data); state="ack"
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
            effect_id,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"C1-M restricted send failed: {completed.stderr[-2048:]!r}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("C1-M restricted sender output must be object")
    validate_json(value)
    return cast(JsonObject, value)


def _invoke(
    *,
    public_root: Path,
    private_root: Path,
    label: str,
    action: str,
    mode: str,
) -> JsonObject:
    socket_path = public_root / f"{label}.sock"
    client_path = public_root / f"{label}-client.sock"
    process, read_fd = _start_recipient(
        socket_path=socket_path,
        private_root=private_root,
        action=action,
        mode=mode,
    )
    _, effect_id, _, _, _ = _protocol_identity(action)
    send = _restricted_send(socket_path=socket_path, client_path=client_path, effect_id=effect_id)
    events, truth = _collect(process, read_fd, expected_sigkill=mode != "healthy")
    socket_path.unlink(missing_ok=True)
    result: JsonObject = {
        "send": send,
        "recipientTruth": truth,
        "evaluatorOnlyPrivateBalanceAfter": _read_private_balance(private_root),
        "publicEndpointClosed": not socket_path.exists() and not client_path.exists(),
    }
    validate_json(result)
    return result


def _prepare_history(
    *, root: Path, public_root: Path, phase: str, history: str, action: str
) -> JsonObject:
    base = root / phase / history
    private_root = root / "recipient-private" / phase / history
    setup = _initialize_private_world(private_root)
    ledger = _sender_ledger(action)
    ledger_bytes = canonical_bytes(ledger)
    ledger_path = base / "sender-ledger.json"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_bytes(ledger_bytes)
    mode = "apply-crash-before-ack" if history == "compensated" else "crash-before-apply"
    fault = _invoke(
        public_root=public_root,
        private_root=private_root,
        label=f"{phase}-{history}-fault",
        action=action,
        mode=mode,
    )
    post_crash_value = json.loads(ledger_path.read_bytes())
    if not isinstance(post_crash_value, dict):
        raise ValueError("C1-M sender ledger must remain an object")
    view = _successor_view(cast(JsonObject, post_crash_value))
    privacy = _privacy_probe(_private_balance_path(private_root))
    classification = classify_successor_view(view)
    result: JsonObject = {
        "schemaVersion": 1,
        "history": history,
        "duplicateSetup": setup,
        "senderLedgerDigest": _digest_bytes(ledger_bytes),
        "successorView": view,
        "successorViewDigest": canonical_digest(view),
        "restrictedSuccessorPrivacyProbe": privacy,
        "classification": classification,
        "faultedCompensation": fault,
        "evaluatorOnlyPrivateBalanceAfterFault": _read_private_balance(private_root),
        "privateRoot": str(private_root),
    }
    validate_json(result)
    return result


def _private_root_from_history(history: JsonObject) -> Path:
    raw = history.get("privateRoot")
    if not isinstance(raw, str):
        raise ValueError("C1-M history lacks privateRoot")
    return Path(raw)


def _supervisor(args: argparse.Namespace) -> None:
    revision = git_revision(Path.cwd(), "Security")
    if args.state_root is None or args.receipt is None:
        raise ValueError("C1-M supervisor requires state-root and receipt")
    args.state_root.mkdir(parents=True, exist_ok=False)
    public_root = Path("/tmp") / f"ordivon-c1m-{os.getpid()}"
    public_root.mkdir(mode=0o777)
    public_root.chmod(0o777)
    try:
        baseline_compensated = _prepare_history(
            root=args.state_root,
            public_root=public_root,
            phase="baseline-naive",
            history="compensated",
            action="naive",
        )
        baseline_uncompensated = _prepare_history(
            root=args.state_root,
            public_root=public_root,
            phase="baseline-naive",
            history="uncompensated",
            action="naive",
        )
        baseline_views_equal = canonical_bytes(
            cast(JsonObject, baseline_compensated["successorView"])
        ) == canonical_bytes(cast(JsonObject, baseline_uncompensated["successorView"]))

        blind_comp = _invoke(
            public_root=public_root,
            private_root=_private_root_from_history(baseline_compensated),
            label="baseline-compensated-blind-retry",
            action="naive",
            mode="healthy",
        )
        blind_uncomp = _invoke(
            public_root=public_root,
            private_root=_private_root_from_history(baseline_uncompensated),
            label="baseline-uncompensated-blind-retry",
            action="naive",
            mode="healthy",
        )

        idem_compensated = _prepare_history(
            root=args.state_root,
            public_root=public_root,
            phase="idempotent-compensator",
            history="compensated",
            action="idempotent",
        )
        idem_uncompensated = _prepare_history(
            root=args.state_root,
            public_root=public_root,
            phase="idempotent-compensator",
            history="uncompensated",
            action="idempotent",
        )
        idem_views_equal = canonical_bytes(
            cast(JsonObject, idem_compensated["successorView"])
        ) == canonical_bytes(cast(JsonObject, idem_uncompensated["successorView"]))
        idem_retry_comp = _invoke(
            public_root=public_root,
            private_root=_private_root_from_history(idem_compensated),
            label="idempotent-compensated-retry",
            action="idempotent",
            mode="healthy",
        )
        idem_retry_uncomp = _invoke(
            public_root=public_root,
            private_root=_private_root_from_history(idem_uncompensated),
            label="idempotent-uncompensated-retry",
            action="idempotent",
            mode="healthy",
        )

        baseline_comp_class = cast(dict[str, object], baseline_compensated["classification"])
        baseline_uncomp_class = cast(dict[str, object], baseline_uncompensated["classification"])
        idem_comp_send = cast(dict[str, object], idem_retry_comp["send"])
        idem_uncomp_send = cast(dict[str, object], idem_retry_uncomp["send"])
        gates = {
            "baselineCompensatedHistoryActuallyRepairedBeforeCrash": baseline_compensated.get(
                "evaluatorOnlyPrivateBalanceAfterFault"
            )
            == _DESIRED_BALANCE,
            "baselineUncompensatedHistoryActuallyUnrepairedBeforeCrash": baseline_uncompensated.get(
                "evaluatorOnlyPrivateBalanceAfterFault"
            )
            == _DUPLICATE_BALANCE,
            "baselineSenderLedgersByteEquivalent": baseline_compensated.get("senderLedgerDigest")
            == baseline_uncompensated.get("senderLedgerDigest"),
            "baselineSuccessorViewsByteEquivalent": baseline_views_equal,
            "baselineBothClassifyUnknown": baseline_comp_class.get("status") == "unknown"
            and baseline_uncomp_class.get("status") == "unknown",
            "baselineUnknownRefusesBlindCompensation": baseline_comp_class.get(
                "blindCompensationAuthorized"
            )
            is False
            and baseline_uncomp_class.get("blindCompensationAuthorized") is False,
            "restrictedSuccessorCannotReadPrivateCompensationState": cast(
                dict[str, object], baseline_compensated["restrictedSuccessorPrivacyProbe"]
            )["readSucceeded"]
            is False
            and cast(dict[str, object], baseline_uncompensated["restrictedSuccessorPrivacyProbe"])[
                "readSucceeded"
            ]
            is False,
            "counterfactualBlindRetryOvercompensatesRepairedHistory": blind_comp.get(
                "evaluatorOnlyPrivateBalanceAfter"
            )
            == _INITIAL_BALANCE,
            "counterfactualBlindRetryRepairsUnrepairedHistory": blind_uncomp.get(
                "evaluatorOnlyPrivateBalanceAfter"
            )
            == _DESIRED_BALANCE,
            "idempotentHistoriesRemainSuccessorViewEquivalent": idem_views_equal,
            "idempotentCompensatorRepairedHistoryRetryIsNoop": idem_retry_comp.get(
                "evaluatorOnlyPrivateBalanceAfter"
            )
            == _DESIRED_BALANCE
            and isinstance(idem_comp_send.get("ack"), dict)
            and cast(dict[str, object], idem_comp_send["ack"]).get("status") == "already-repaired",
            "idempotentCompensatorUnrepairedHistoryRetryAppliesRepair": idem_retry_uncomp.get(
                "evaluatorOnlyPrivateBalanceAfter"
            )
            == _DESIRED_BALANCE
            and isinstance(idem_uncomp_send.get("ack"), dict)
            and cast(dict[str, object], idem_uncomp_send["ack"]).get("status") == "applied",
            "idempotentCompensatorConvergesBothHiddenHistories": idem_retry_comp.get(
                "evaluatorOnlyPrivateBalanceAfter"
            )
            == idem_retry_uncomp.get("evaluatorOnlyPrivateBalanceAfter")
            == _DESIRED_BALANCE,
            "idempotentCompensatorRequiresNoCallerReadAuthority": cast(
                dict[str, object], idem_compensated["restrictedSuccessorPrivacyProbe"]
            )["readSucceeded"]
            is False
            and cast(dict[str, object], idem_uncompensated["restrictedSuccessorPrivacyProbe"])[
                "readSucceeded"
            ]
            is False,
            "privateWorldContainsOnlyConsequenceState": all(
                _private_world_inventory(_private_root_from_history(history)) == ["balance.json"]
                for history in (
                    baseline_compensated,
                    baseline_uncompensated,
                    idem_compensated,
                    idem_uncompensated,
                )
            ),
            "allPublicEndpointsClosed": all(
                item.get("publicEndpointClosed") is True
                for item in (
                    cast(JsonObject, baseline_compensated["faultedCompensation"]),
                    cast(JsonObject, baseline_uncompensated["faultedCompensation"]),
                    blind_comp,
                    blind_uncomp,
                    cast(JsonObject, idem_compensated["faultedCompensation"]),
                    cast(JsonObject, idem_uncompensated["faultedCompensation"]),
                    idem_retry_comp,
                    idem_retry_uncomp,
                )
            ),
            "protocolUpgradeUsesDistinctEffectIdentity": _NAIVE_COMPENSATION_EFFECT_ID
            != _IDEMPOTENT_COMPENSATION_EFFECT_ID
            and _compensation_binding("naive") != _compensation_binding("idempotent"),
            "allDeliveryAttemptsUsedRestrictedUid": all(
                cast(dict[str, object], item["send"])["uid"] == 65534
                for item in (
                    cast(JsonObject, baseline_compensated["faultedCompensation"]),
                    cast(JsonObject, baseline_uncompensated["faultedCompensation"]),
                    blind_comp,
                    blind_uncomp,
                    cast(JsonObject, idem_compensated["faultedCompensation"]),
                    cast(JsonObject, idem_uncompensated["faultedCompensation"]),
                    idem_retry_comp,
                    idem_retry_uncomp,
                )
            ),
            "noNetworkOrExternalTargetConsumed": True,
        }
        residual_entries = sorted(item.name for item in public_root.iterdir())
        gates["publicCapabilityRootClosedToZero"] = residual_entries == []
        passed = all(gates.values())
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1m-compensation-information-loss-acceptance",
            "status": "accepted" if passed else "failed",
            "securityRevision": revision,
            "compensationBindings": {
                "baselineNaive": _compensation_binding("naive"),
                "idempotentCompensator": _compensation_binding("idempotent"),
            },
            "baselineNaive": {
                "compensated": baseline_compensated,
                "uncompensated": baseline_uncompensated,
                "counterfactualBlindRetry": {
                    "compensatedHistory": blind_comp,
                    "uncompensatedHistory": blind_uncomp,
                },
            },
            "privateWorldInventories": {
                "baselineCompensated": _private_world_inventory(
                    _private_root_from_history(baseline_compensated)
                ),
                "baselineUncompensated": _private_world_inventory(
                    _private_root_from_history(baseline_uncompensated)
                ),
                "idempotentCompensated": _private_world_inventory(
                    _private_root_from_history(idem_compensated)
                ),
                "idempotentUncompensated": _private_world_inventory(
                    _private_root_from_history(idem_uncompensated)
                ),
            },
            "idempotentCompensator": {
                "compensated": idem_compensated,
                "uncompensated": idem_uncompensated,
                "retry": {
                    "compensatedHistory": idem_retry_comp,
                    "uncompensatedHistory": idem_retry_uncomp,
                },
            },
            "gates": gates,
            "interpretation": {
                "compensationInformationLossForcesUnknown": passed,
                "blindNaiveCompensationRetrySafe": False,
                "intrinsicallyIdempotentCompensatorMakesRetrySafe": passed,
                "callerHistoricalCertaintyRequiredForSafeRetry": False,
                "callerPrivateStateReadAuthorityRequired": False,
                "durableCompensationReceiptRequiredForThisCandidate": False,
                "sharedAtomicBoundaryRequiredForThisCandidate": False,
                "genericTransactionManagerRequired": False,
            },
        }
        write_receipt(args.receipt, receipt)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
        if not passed:
            raise SystemExit(1)
    finally:
        if public_root.exists() and not any(public_root.iterdir()):
            public_root.rmdir()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run C1-M compensation information-loss acceptance over an opaque "
            "downstream private world."
        )
    )
    parser.add_argument("--recipient", action="store_true")
    parser.add_argument("--action", choices=("naive", "idempotent"))
    parser.add_argument(
        "--mode",
        choices=("crash-before-apply", "apply-crash-before-ack", "healthy"),
    )
    parser.add_argument("--socket-path", type=Path)
    parser.add_argument("--private-root", type=Path)
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
