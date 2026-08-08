from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json
from ordivon_security.providers.windows_kvm import (
    _load_object,
    _process_identity,
    _process_start_time,
    _replace_private_json,
)


class RecoveryClaimStaleError(RuntimeError):
    """The exact ledger generation changed before a successor acquired recovery authority."""


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _identity_alive(pid: object, start_time: object) -> bool:
    if not isinstance(pid, int) or pid < 1 or not isinstance(start_time, int):
        return False
    identity = _process_identity(pid)
    return identity is not None and identity[1] == start_time and identity[0] != "Z"


def _claims_root(state_root: Path) -> Path:
    root = state_root / "recovery-claims"
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    return root


def _claim_paths(state_root: Path, run_token: str) -> tuple[Path, Path]:
    if not run_token.startswith(("s5-", "s6-")) or "/" in run_token or run_token in {"s5-", "s6-"}:
        raise ValueError("Windows fabric recovery run token is unsafe")
    root = _claims_root(state_root)
    return root / f"{run_token}.lock", root / f"{run_token}.json"


@dataclass(slots=True)
class WindowsFabricRecoveryGate:
    run_token: str
    lock_path: Path
    claim_path: Path
    fd: int
    released: bool = False

    def read_claim(self) -> JsonObject | None:
        if not self.claim_path.exists():
            return None
        try:
            return _load_object(self.claim_path, "Windows fabric recovery claim")
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def release(self) -> None:
        if self.released:
            return
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)
        self.released = True

    def __enter__(self) -> WindowsFabricRecoveryGate:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


@dataclass(slots=True)
class WindowsFabricRecoveryClaim:
    gate: WindowsFabricRecoveryGate
    claim: JsonObject
    released: bool = False

    def release(self, *, disposition: str = "released") -> None:
        if self.released:
            return
        final = dict(self.claim)
        final["state"] = disposition
        final["releasedAtNs"] = time.time_ns()
        validate_json(final)
        _replace_private_json(self.gate.claim_path, cast(JsonObject, final))
        self.gate.release()
        self.claim = cast(JsonObject, final)
        self.released = True

    def __enter__(self) -> WindowsFabricRecoveryClaim:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release(disposition="released" if exc is None else "released-after-error")


def try_acquire_windows_fabric_recovery_gate(
    state_root: Path,
    *,
    run_token: str,
) -> WindowsFabricRecoveryGate | None:
    lock_path, claim_path = _claim_paths(state_root, run_token)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        return WindowsFabricRecoveryGate(
            run_token=run_token,
            lock_path=lock_path,
            claim_path=claim_path,
            fd=fd,
        )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def acquire_windows_fabric_successor_claim(
    state_root: Path,
    *,
    ledger_path: Path,
    expected_ledger_digest: str,
    purpose: str,
) -> WindowsFabricRecoveryClaim | None:
    if ledger_path.parent != state_root / "run-ledgers" or ledger_path.suffix != ".json":
        raise ValueError("successor claim ledger path is outside the exact Range ledger root")
    run_token = ledger_path.stem
    gate = try_acquire_windows_fabric_recovery_gate(state_root, run_token=run_token)
    if gate is None:
        return None
    try:
        if ledger_path.is_symlink() or not ledger_path.is_file():
            raise RecoveryClaimStaleError("successor claim ledger disappeared before acquisition")
        ledger_bytes = ledger_path.read_bytes()
        current_digest = _digest_bytes(ledger_bytes)
        if current_digest != expected_ledger_digest:
            raise RecoveryClaimStaleError(
                "successor claim ledger generation changed before acquisition"
            )
        ledger = _load_object(ledger_path, "successor claim Range ledger")
        if _identity_alive(ledger.get("ownerPid"), ledger.get("ownerStartTime")):
            raise RuntimeError(
                "successor claim refuses a Range whose original owner is still alive"
            )
        claimant_start = _process_start_time(os.getpid())
        if claimant_start is None:
            raise RuntimeError("successor claim process identity is not observable")
        effect = ledger.get("actorReplacementRequest")
        effect_id = effect.get("effectId") if isinstance(effect, dict) else None
        base: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-fabric-successor-claim",
            "state": "held",
            "runToken": run_token,
            "rangeSessionId": ledger.get("rangeSessionId"),
            "rangeId": ledger.get("rangeId"),
            "purpose": purpose,
            "ledgerDigest": current_digest,
            "claimantPid": os.getpid(),
            "claimantStartTime": claimant_start,
            "predecessorOwnerPid": ledger.get("ownerPid"),
            "predecessorOwnerStartTime": ledger.get("ownerStartTime"),
            "effectId": effect_id,
            "acquiredAtNs": time.time_ns(),
        }
        claim_id = "recovery-claim:" + canonical_digest(base).removeprefix("sha256:")[:24]
        base["claimId"] = claim_id
        validate_json(base)
        _replace_private_json(gate.claim_path, base)
        return WindowsFabricRecoveryClaim(gate=gate, claim=base)
    except BaseException:
        gate.release()
        raise
