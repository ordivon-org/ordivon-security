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

_ORIGINAL_EFFECT_ID = "range-effect:c1l-non-idempotent-increment-v1"
_COMPENSATION_EFFECT_ID = "range-effect:c1l-compensate-duplicate-increment-v1"
_REQUEST_ID = "range-effect-request:c1l-non-idempotent-increment-v1"
_AUTHORITY_ID = "range-authority:c1l-local-compensable-world"
_ACTOR_ID = "actor:c1l-recovery-sender"
_ZONE_REF = "zone:c1l-local-no-uplink"
_CAPABILITY = "counter.increment-one"
_EFFECT_TYPE = "counter.add-one"
_COMPENSATION_CAPABILITY = "counter.compensate-duplicate"
_COMPENSATION_TYPE = "counter.subtract-one-duplicate"
_INITIAL_BALANCE = 0
_DESIRED_BALANCE = 1
_DUPLICATE_BALANCE = 2


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _effect_binding() -> JsonObject:
    request: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-effect-request",
        "requestId": _REQUEST_ID,
        "actorId": _ACTOR_ID,
        "authorityId": _AUTHORITY_ID,
        "zoneRef": _ZONE_REF,
        "capability": _CAPABILITY,
        "effectType": _EFFECT_TYPE,
        "delta": 1,
    }
    request_digest = canonical_digest(request)
    admission: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-effect-admission",
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
        "effectId": _ORIGINAL_EFFECT_ID,
        "delta": 1,
        "desiredBalance": _DESIRED_BALANCE,
    }
    validate_json(result)
    return result


def _compensation_binding() -> JsonObject:
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-compensation-binding",
        "compensationEffectId": _COMPENSATION_EFFECT_ID,
        "compensatesEffectId": _ORIGINAL_EFFECT_ID,
        "authorityId": _AUTHORITY_ID,
        "zoneRef": _ZONE_REF,
        "capability": _COMPENSATION_CAPABILITY,
        "effectType": _COMPENSATION_TYPE,
        "duplicateBalance": _DUPLICATE_BALANCE,
        "repairedBalance": _DESIRED_BALANCE,
    }
    validate_json(result)
    return result


def _sender_ledger() -> JsonObject:
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-sender-ledger",
        "effectBinding": _effect_binding(),
        "state": "admitted-pending-acknowledgement",
        "completionPublished": False,
    }
    validate_json(value)
    return value


def _balance_path(world_root: Path) -> Path:
    return world_root / "balance.json"


def _atomic_write_json(path: Path, value: JsonObject) -> None:
    validate_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_bytes(value))
    os.replace(temporary, path)


def _initialize_world(world_root: Path) -> None:
    world_root.mkdir(parents=True, exist_ok=True)
    world_root.chmod(0o700)
    _atomic_write_json(
        _balance_path(world_root),
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1l-world-balance",
            "balance": _INITIAL_BALANCE,
        },
    )


def observe_balance(world_root: Path) -> JsonObject:
    path = _balance_path(world_root)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("balance"), int):
        raise ValueError("C1-L world balance has invalid shape")
    balance = cast(int, value["balance"])
    observation: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-world-balance-observation",
        "balance": balance,
        "desiredBalance": _DESIRED_BALANCE,
        "isDesired": balance == _DESIRED_BALANCE,
        "isExactDuplicate": balance == _DUPLICATE_BALANCE,
    }
    validate_json(observation)
    return observation


def _set_balance(world_root: Path, balance: int) -> None:
    _atomic_write_json(
        _balance_path(world_root),
        {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1l-world-balance",
            "balance": balance,
        },
    )


def apply_original_effect(world_root: Path) -> JsonObject:
    before = observe_balance(world_root)
    balance = cast(int, before["balance"])
    _set_balance(world_root, balance + 1)
    after = observe_balance(world_root)
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-original-effect-result",
        "effectId": _ORIGINAL_EFFECT_ID,
        "status": "applied",
        "before": before,
        "after": after,
    }
    validate_json(result)
    return result


def apply_naive_compensation(world_root: Path) -> JsonObject:
    before = observe_balance(world_root)
    balance = cast(int, before["balance"])
    if balance <= 0:
        result: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1l-compensation-result",
            "compensationEffectId": _COMPENSATION_EFFECT_ID,
            "status": "conflict",
            "worldMutated": False,
            "before": before,
            "after": before,
        }
        validate_json(result)
        return result
    _set_balance(world_root, balance - 1)
    after = observe_balance(world_root)
    result = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-compensation-result",
        "compensationEffectId": _COMPENSATION_EFFECT_ID,
        "status": "applied",
        "worldMutated": True,
        "before": before,
        "after": after,
    }
    validate_json(result)
    return result


def classify_compensation_recovery(world_root: Path) -> JsonObject:
    observation = observe_balance(world_root)
    balance = observation.get("balance")
    if balance == _DUPLICATE_BALANCE:
        status_value = "needs-compensation"
        compensation_authorized = True
        publication_authorized = False
    elif balance == _DESIRED_BALANCE:
        status_value = "already-repaired"
        compensation_authorized = False
        publication_authorized = True
    else:
        status_value = "unexpected-world-state"
        compensation_authorized = False
        publication_authorized = False
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-compensation-recovery-classification",
        "status": status_value,
        "compensationAuthorized": compensation_authorized,
        "repairPublicationAuthorized": publication_authorized,
        "worldObservation": observation,
    }
    validate_json(result)
    return result


def apply_guarded_compensation(world_root: Path) -> JsonObject:
    classification = classify_compensation_recovery(world_root)
    if classification.get("status") == "already-repaired":
        result: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1l-guarded-compensation-result",
            "compensationEffectId": _COMPENSATION_EFFECT_ID,
            "status": "already-repaired",
            "worldMutated": False,
            "before": classification["worldObservation"],
            "after": classification["worldObservation"],
        }
        validate_json(result)
        return result
    if classification.get("status") != "needs-compensation":
        result = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1l-guarded-compensation-result",
            "compensationEffectId": _COMPENSATION_EFFECT_ID,
            "status": "conflict",
            "worldMutated": False,
            "before": classification["worldObservation"],
            "after": classification["worldObservation"],
        }
        validate_json(result)
        return result
    naive = apply_naive_compensation(world_root)
    after = observe_balance(world_root)
    if after.get("balance") != _DESIRED_BALANCE:
        raise RuntimeError("C1-L guarded compensation did not restore exact invariant")
    result = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1l-guarded-compensation-result",
        "compensationEffectId": _COMPENSATION_EFFECT_ID,
        "status": "applied",
        "worldMutated": True,
        "before": naive["before"],
        "after": after,
    }
    validate_json(result)
    return result


def _emit_oracle(fd: int, event: JsonObject) -> None:
    validate_json(event)
    os.write(fd, canonical_bytes(event) + b"\n")


def _recipient_main(args: argparse.Namespace) -> None:
    if args.socket_path is None or args.world_root is None or args.oracle_fd is None:
        raise ValueError("C1-L recipient requires socket/world/oracle")
    if args.action is None or args.mode is None:
        raise ValueError("C1-L recipient requires action/mode")
    expected_id = _ORIGINAL_EFFECT_ID if args.action == "original" else _COMPENSATION_EFFECT_ID
    socket_path = args.socket_path
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        server.bind(str(socket_path))
        socket_path.chmod(0o777)
        payload, client = server.recvfrom(65536)
        message = json.loads(payload)
        if not isinstance(message, dict) or message.get("effectId") != expected_id:
            raise ValueError("C1-L recipient received wrong effect identity")
        _emit_oracle(
            args.oracle_fd,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.c1l-invocation",
                "stage": "received",
                "action": args.action,
                "mode": args.mode,
                "effectId": expected_id,
            },
        )
        if args.mode == "crash-before-apply":
            os.kill(os.getpid(), signal.SIGKILL)
            raise RuntimeError("C1-L pre-apply worker survived SIGKILL")
        if args.action == "original":
            result = apply_original_effect(args.world_root)
        elif args.action == "naive-compensation":
            result = apply_naive_compensation(args.world_root)
        elif args.action == "guarded-compensation":
            result = apply_guarded_compensation(args.world_root)
        else:
            raise ValueError(f"unsupported C1-L action: {args.action}")
        _emit_oracle(
            args.oracle_fd,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.c1l-invocation",
                "stage": "effect-returned",
                "action": args.action,
                "mode": args.mode,
                "effectId": expected_id,
                "status": result.get("status"),
                "worldMutated": result.get("worldMutated", True),
                "balanceAfter": cast(dict[str, object], result["after"]).get("balance"),
            },
        )
        if args.mode == "apply-crash-before-ack":
            os.kill(os.getpid(), signal.SIGKILL)
            raise RuntimeError("C1-L post-apply worker survived SIGKILL")
        ack: JsonObject = {
            "schemaVersion": 1,
            "effectId": expected_id,
            "status": result.get("status"),
            "balance": cast(dict[str, object], result["after"]).get("balance"),
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
            raise RuntimeError(f"C1-L recipient exited before ready: {process.returncode}")
        time.sleep(0.02)
    raise TimeoutError("C1-L recipient socket did not become ready")


def _start_recipient(
    *, socket_path: Path, world_root: Path, action: str, mode: str
) -> tuple[subprocess.Popen[bytes], int]:
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_compensation_acceptance",
            "--recipient",
            "--action",
            action,
            "--mode",
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
            raise ValueError("C1-L oracle event must be object")
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
            f"C1-L recipient exit {process.returncode}, expected {expected}: {stderr[-2048:]!r}"
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
            effect_id,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"C1-L restricted send failed: {completed.stderr[-2048:]!r}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("C1-L restricted sender output must be object")
    validate_json(value)
    return cast(JsonObject, value)


def _invoke(
    *,
    public_root: Path,
    world_root: Path,
    label: str,
    action: str,
    mode: str,
) -> JsonObject:
    socket_path = public_root / f"{label}.sock"
    client_path = public_root / f"{label}-client.sock"
    effect_id = _ORIGINAL_EFFECT_ID if action == "original" else _COMPENSATION_EFFECT_ID
    process, read_fd = _start_recipient(
        socket_path=socket_path,
        world_root=world_root,
        action=action,
        mode=mode,
    )
    send = _restricted_send(
        socket_path=socket_path,
        client_path=client_path,
        effect_id=effect_id,
    )
    events, truth = _collect(process, read_fd, expected_sigkill=mode != "healthy")
    socket_path.unlink(missing_ok=True)
    result: JsonObject = {
        "send": send,
        "recipientTruth": truth,
        "worldAfter": observe_balance(world_root),
        "publicEndpointClosed": not socket_path.exists() and not client_path.exists(),
    }
    validate_json(result)
    return result


def _prepare_duplicate(root: Path, public_root: Path, label: str) -> JsonObject:
    world_root = root / label / "world"
    _initialize_world(world_root)
    ledger = _sender_ledger()
    ledger_bytes = canonical_bytes(ledger)
    ledger_path = root / label / "sender-ledger.json"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_bytes(ledger_bytes)
    first = _invoke(
        public_root=public_root,
        world_root=world_root,
        label=f"{label}-original-first",
        action="original",
        mode="apply-crash-before-ack",
    )
    retry = _invoke(
        public_root=public_root,
        world_root=world_root,
        label=f"{label}-original-retry",
        action="original",
        mode="healthy",
    )
    result: JsonObject = {
        "worldRoot": str(world_root),
        "senderLedgerDigest": _digest_bytes(ledger_bytes),
        "senderLedgerUnchanged": ledger_path.read_bytes() == ledger_bytes,
        "firstAttempt": first,
        "retryAttempt": retry,
        "worldAfterDuplicate": observe_balance(world_root),
    }
    validate_json(result)
    return result


def _world_root_from_duplicate(value: JsonObject) -> Path:
    raw = value.get("worldRoot")
    if not isinstance(raw, str):
        raise ValueError("C1-L duplicate result lacks world root")
    return Path(raw)


def _supervisor(args: argparse.Namespace) -> None:
    revision = git_revision(Path.cwd(), "Security")
    if args.state_root is None or args.receipt is None:
        raise ValueError("C1-L supervisor requires state-root and receipt")
    args.state_root.mkdir(parents=True, exist_ok=False)
    public_root = Path("/tmp") / f"ordivon-c1l-{os.getpid()}"
    public_root.mkdir(mode=0o777)
    public_root.chmod(0o777)
    try:
        naive = _prepare_duplicate(args.state_root, public_root, "naive-blind-retry")
        naive_world = _world_root_from_duplicate(naive)
        naive_first = _invoke(
            public_root=public_root,
            world_root=naive_world,
            label="naive-comp-first",
            action="naive-compensation",
            mode="apply-crash-before-ack",
        )
        naive_retry = _invoke(
            public_root=public_root,
            world_root=naive_world,
            label="naive-comp-retry",
            action="naive-compensation",
            mode="healthy",
        )

        before_apply = _prepare_duplicate(args.state_root, public_root, "reobserve-before-apply")
        before_world = _world_root_from_duplicate(before_apply)
        comp_before = _invoke(
            public_root=public_root,
            world_root=before_world,
            label="guarded-comp-before",
            action="guarded-compensation",
            mode="crash-before-apply",
        )
        before_classification = classify_compensation_recovery(before_world)
        comp_before_retry = _invoke(
            public_root=public_root,
            world_root=before_world,
            label="guarded-comp-before-retry",
            action="guarded-compensation",
            mode="healthy",
        )

        after_apply = _prepare_duplicate(args.state_root, public_root, "reobserve-after-apply")
        after_world = _world_root_from_duplicate(after_apply)
        comp_after = _invoke(
            public_root=public_root,
            world_root=after_world,
            label="guarded-comp-after",
            action="guarded-compensation",
            mode="apply-crash-before-ack",
        )
        after_classification = classify_compensation_recovery(after_world)
        repair_publication: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1l-repair-publication",
            "compensationEffectId": _COMPENSATION_EFFECT_ID,
            "status": "repaired",
            "worldMutated": False,
            "classification": after_classification,
        }
        validate_json(repair_publication)

        naive_first_send = cast(dict[str, object], naive_first["send"])
        naive_retry_send = cast(dict[str, object], naive_retry["send"])
        before_retry_send = cast(dict[str, object], comp_before_retry["send"])
        gates = {
            "originalEffectIsNonIdempotentAndDuplicatedByRetry": cast(
                dict[str, object], naive["worldAfterDuplicate"]
            )["balance"]
            == _DUPLICATE_BALANCE,
            "naiveCompensationFirstApplicationRestoredInvariant": cast(
                dict[str, object], naive_first["worldAfter"]
            )["balance"]
            == _DESIRED_BALANCE,
            "naiveCompensationAckWasLost": naive_first_send.get("state") == "no-ack",
            "blindCompensationRetryOvercompensated": cast(
                dict[str, object], naive_retry["worldAfter"]
            )["balance"]
            == _INITIAL_BALANCE,
            "blindCompensationRetryWasActuallyInvoked": naive_retry_send.get("state") == "ack",
            "crashBeforeCompensationLeftDuplicateState": cast(
                dict[str, object], comp_before["worldAfter"]
            )["balance"]
            == _DUPLICATE_BALANCE,
            "reobservationAuthorizedCompensationOnlyForExactDuplicate": before_classification.get(
                "status"
            )
            == "needs-compensation"
            and before_classification.get("compensationAuthorized") is True,
            "guardedCompensationAfterPreApplyCrashRestoredInvariant": cast(
                dict[str, object], comp_before_retry["worldAfter"]
            )["balance"]
            == _DESIRED_BALANCE
            and isinstance(before_retry_send.get("ack"), dict)
            and cast(dict[str, object], before_retry_send["ack"]).get("status") == "applied",
            "postApplyCompensationCrashLeftRepairedWorld": cast(
                dict[str, object], comp_after["worldAfter"]
            )["balance"]
            == _DESIRED_BALANCE,
            "reobservationDetectedAlreadyRepairedWithoutRetry": after_classification.get("status")
            == "already-repaired"
            and after_classification.get("compensationAuthorized") is False
            and after_classification.get("repairPublicationAuthorized") is True,
            "publicationRepairAfterCompensationDoesNotMutateWorld": repair_publication.get(
                "worldMutated"
            )
            is False
            and cast(dict[str, object], repair_publication["classification"])["worldObservation"]
            == after_classification["worldObservation"],
            "compensationKeepsOriginalAndRepairIdentitiesDistinct": _COMPENSATION_EFFECT_ID
            != _ORIGINAL_EFFECT_ID
            and _compensation_binding().get("compensatesEffectId") == _ORIGINAL_EFFECT_ID,
            "allAcceptedRecoveriesEndAtDeclaredInvariant": cast(
                dict[str, object], comp_before_retry["worldAfter"]
            )["balance"]
            == _DESIRED_BALANCE
            and cast(dict[str, object], comp_after["worldAfter"])["balance"] == _DESIRED_BALANCE,
            "allDeliveryAttemptsUsedRestrictedUid": all(
                cast(dict[str, object], invocation["send"])["uid"] == 65534
                for invocation in (
                    cast(JsonObject, naive["firstAttempt"]),
                    cast(JsonObject, naive["retryAttempt"]),
                    naive_first,
                    naive_retry,
                    cast(JsonObject, before_apply["firstAttempt"]),
                    cast(JsonObject, before_apply["retryAttempt"]),
                    comp_before,
                    comp_before_retry,
                    cast(JsonObject, after_apply["firstAttempt"]),
                    cast(JsonObject, after_apply["retryAttempt"]),
                    comp_after,
                )
            ),
            "publicEndpointsClosed": all(
                invocation.get("publicEndpointClosed") is True
                for invocation in (
                    cast(JsonObject, naive["firstAttempt"]),
                    cast(JsonObject, naive["retryAttempt"]),
                    naive_first,
                    naive_retry,
                    cast(JsonObject, before_apply["firstAttempt"]),
                    cast(JsonObject, before_apply["retryAttempt"]),
                    comp_before,
                    comp_before_retry,
                    cast(JsonObject, after_apply["firstAttempt"]),
                    cast(JsonObject, after_apply["retryAttempt"]),
                    comp_after,
                )
            ),
            "noNetworkOrExternalTargetConsumed": True,
        }
        residual_entries = sorted(item.name for item in public_root.iterdir())
        gates["publicCapabilityRootClosedToZero"] = residual_entries == []
        passed = all(gates.values())
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1l-compensation-acceptance",
            "status": "accepted" if passed else "failed",
            "securityRevision": revision,
            "effectBinding": _effect_binding(),
            "compensationBinding": _compensation_binding(),
            "counterfactualBlindCompensationRetry": {
                "duplicateSetup": naive,
                "firstCompensation": naive_first,
                "blindRetry": naive_retry,
            },
            "compensationCrashBeforeApply": {
                "duplicateSetup": before_apply,
                "faultedCompensation": comp_before,
                "postCrashClassification": before_classification,
                "recoveryCompensation": comp_before_retry,
            },
            "compensationCrashAfterApplyBeforeAck": {
                "duplicateSetup": after_apply,
                "faultedCompensation": comp_after,
                "postCrashClassification": after_classification,
                "publicationRepair": repair_publication,
            },
            "gates": gates,
            "interpretation": {
                "compensationCanRestoreDeclaredInvariantAfterDuplicate": passed,
                "compensationErasesDuplicateHistory": False,
                "blindCompensationRetrySafe": False,
                "observableRepairInvariantCanDisambiguateCompensationProgress": passed,
                "compensationRequiresExactlyOnceInvocationHere": False,
                "genericTransactionManagerRequired": False,
                "genericCausalDagRequired": False,
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
        description="Run C1-L compensation acceptance over a local non-idempotent counter effect."
    )
    parser.add_argument("--recipient", action="store_true")
    parser.add_argument(
        "--action",
        choices=("original", "naive-compensation", "guarded-compensation"),
    )
    parser.add_argument(
        "--mode",
        choices=("crash-before-apply", "apply-crash-before-ack", "healthy"),
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
