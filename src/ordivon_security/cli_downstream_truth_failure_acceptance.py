from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.cli_compensation_information_loss_acceptance import (
    _DESIRED_BALANCE,
    _DUPLICATE_BALANCE,
    _compensation_binding,
)
from ordivon_security.cli_windows_kvm_c1a_acceptance import _git_revision
from ordivon_security.cli_windows_kvm_s3_acceptance import _write_receipt

_TRUTH_RECOVERY_ID = "truth-recovery:c1n-sealed-state-witness-v1"
_WITNESS_KIND = "ordivon.security.c1n-sealed-state-witness"
_PRIVATE_KIND = "ordivon.security.c1n-private-balance"


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _balance_object(balance: int) -> JsonObject:
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": _PRIVATE_KIND,
        "balance": balance,
    }
    validate_json(value)
    return value


def _canonical_path(root: Path) -> Path:
    return root / "balance.json"


def _write_balance(root: Path, balance: int) -> None:
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    _atomic_write(_canonical_path(root), canonical_bytes(_balance_object(balance)))
    _canonical_path(root).chmod(0o600)


def _tree_inventory(root: Path) -> list[JsonObject]:
    if not root.exists():
        return []
    items: list[JsonObject] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() or p.is_symlink()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            payload = os.readlink(path).encode()
            entry_type = "symlink"
        else:
            payload = path.read_bytes()
            entry_type = "file"
        item: JsonObject = {
            "path": relative,
            "type": entry_type,
            "byteLength": len(payload),
            "sha256": _sha256(payload),
        }
        validate_json(item)
        items.append(item)
    return items


def _tree_digest(root: Path) -> str:
    value: JsonObject = {"inventory": _tree_inventory(root)}
    validate_json(value)
    return canonical_digest(value)


def _parse_balance_bytes(data: bytes) -> tuple[str, int | None, str | None]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "corrupt", None, "invalid-json"
    if not isinstance(value, dict):
        return "corrupt", None, "not-object"
    if value.get("schemaVersion") != 1 or value.get("kind") != _PRIVATE_KIND:
        return "corrupt", None, "wrong-schema-or-kind"
    balance = value.get("balance")
    if not isinstance(balance, int):
        return "corrupt", None, "balance-not-int"
    return "valid", balance, None


def inspect_authority_truth(root: Path) -> JsonObject:
    canonical = _canonical_path(root)
    branches = root / "branches"
    if canonical.exists() or canonical.is_symlink():
        if not canonical.is_file() or canonical.is_symlink():
            result: JsonObject = {
                "status": "corrupt",
                "reason": "canonical-not-regular-file",
                "balance": None,
                "candidates": [],
            }
            validate_json(result)
            return result
        status, balance, reason = _parse_balance_bytes(canonical.read_bytes())
        result = {
            "status": "healthy" if status == "valid" else "corrupt",
            "reason": reason,
            "balance": balance,
            "candidates": [],
        }
        validate_json(result)
        return result

    candidate_values: list[JsonObject] = []
    if branches.exists():
        for candidate in sorted(path for path in branches.glob("*.json") if path.is_file()):
            raw = candidate.read_bytes()
            status, balance, reason = _parse_balance_bytes(raw)
            item: JsonObject = {
                "name": candidate.name,
                "sha256": _sha256(raw),
                "status": status,
                "balance": balance,
                "reason": reason,
            }
            validate_json(item)
            candidate_values.append(item)
    valid_balances = {
        cast(int, item["balance"])
        for item in candidate_values
        if item.get("status") == "valid" and isinstance(item.get("balance"), int)
    }
    if candidate_values and len(valid_balances) > 1:
        result = {
            "status": "fork-conflict",
            "reason": "multiple-authoritative-candidates-disagree",
            "balance": None,
            "candidates": candidate_values,
        }
    elif candidate_values:
        result = {
            "status": "ambiguous-candidates",
            "reason": "canonical-authority-missing",
            "balance": None,
            "candidates": candidate_values,
        }
    else:
        result = {
            "status": "missing",
            "reason": "canonical-truth-absent",
            "balance": None,
            "candidates": [],
        }
    validate_json(result)
    return result


def apply_ensure_repaired(root: Path) -> JsonObject:
    before_tree = _tree_digest(root)
    observation = inspect_authority_truth(root)
    status = observation.get("status")
    if status != "healthy":
        action_status = (
            "truth-unavailable" if status in {"missing", "corrupt"} else "truth-conflict"
        )
        mutated = False
    else:
        balance = observation.get("balance")
        if balance == _DUPLICATE_BALANCE:
            _write_balance(root, _DESIRED_BALANCE)
            action_status = "applied"
            mutated = True
        elif balance == _DESIRED_BALANCE:
            action_status = "already-repaired"
            mutated = False
        else:
            action_status = "conflict"
            mutated = False
    after_tree = _tree_digest(root)
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1n-ensure-repaired-result",
        "compensationBinding": _compensation_binding("idempotent"),
        "truthObservation": observation,
        "status": action_status,
        "worldMutated": mutated,
        "treeDigestBefore": before_tree,
        "treeDigestAfter": after_tree,
    }
    validate_json(result)
    return result


def _seal_witness(witness_path: Path, *, balance: int, lineage: str) -> JsonObject:
    state = _balance_object(balance)
    witness: JsonObject = {
        "schemaVersion": 1,
        "kind": _WITNESS_KIND,
        "truthRecoveryId": _TRUTH_RECOVERY_ID,
        "lineage": lineage,
        "state": state,
        "stateDigest": canonical_digest(state),
    }
    witness["witnessDigest"] = canonical_digest(witness)
    validate_json(witness)
    _atomic_write(witness_path, canonical_bytes(witness))
    witness_path.chmod(0o400)
    return witness


def _read_verified_witness(witness_path: Path, *, expected_lineage: str) -> JsonObject:
    try:
        raw = witness_path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        result: JsonObject = {
            "status": "invalid-witness",
            "reason": "unreadable-or-invalid-json",
            "balance": None,
        }
        validate_json(result)
        return result
    if not isinstance(value, dict):
        result = {"status": "invalid-witness", "reason": "not-object", "balance": None}
        validate_json(result)
        return result
    supplied_digest = value.get("witnessDigest")
    unsigned = dict(value)
    unsigned.pop("witnessDigest", None)
    if supplied_digest != canonical_digest(cast(JsonObject, unsigned)):
        result = {"status": "invalid-witness", "reason": "digest-mismatch", "balance": None}
        validate_json(result)
        return result
    if (
        value.get("schemaVersion") != 1
        or value.get("kind") != _WITNESS_KIND
        or value.get("truthRecoveryId") != _TRUTH_RECOVERY_ID
        or value.get("lineage") != expected_lineage
    ):
        result = {"status": "invalid-witness", "reason": "identity-mismatch", "balance": None}
        validate_json(result)
        return result
    state = value.get("state")
    if not isinstance(state, dict) or value.get("stateDigest") != canonical_digest(
        cast(JsonObject, state)
    ):
        result = {"status": "invalid-witness", "reason": "state-digest-mismatch", "balance": None}
        validate_json(result)
        return result
    encoded = canonical_bytes(cast(JsonObject, state))
    parse_status, balance, reason = _parse_balance_bytes(encoded)
    if parse_status != "valid" or balance not in {_DESIRED_BALANCE, _DUPLICATE_BALANCE}:
        result = {
            "status": "invalid-witness",
            "reason": reason or "balance-outside-recovery-contract",
            "balance": None,
        }
        validate_json(result)
        return result
    result = {
        "status": "verified",
        "reason": None,
        "balance": balance,
        "witnessDigest": supplied_digest,
        "stateDigest": value.get("stateDigest"),
        "lineage": expected_lineage,
    }
    validate_json(result)
    return result


def restore_truth_from_witness(root: Path, witness_path: Path, *, lineage: str) -> JsonObject:
    before = inspect_authority_truth(root)
    witness = _read_verified_witness(witness_path, expected_lineage=lineage)
    if before.get("status") == "healthy":
        result: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1n-truth-restore-result",
            "truthRecoveryId": _TRUTH_RECOVERY_ID,
            "status": "refused-healthy-local-truth",
            "worldMutated": False,
            "localTruthBefore": before,
            "witness": witness,
            "localTruthAfter": before,
        }
        validate_json(result)
        return result
    if witness.get("status") != "verified" or not isinstance(witness.get("balance"), int):
        result = {
            "schemaVersion": 1,
            "kind": "ordivon.security.c1n-truth-restore-result",
            "truthRecoveryId": _TRUTH_RECOVERY_ID,
            "status": "invalid-witness",
            "worldMutated": False,
            "localTruthBefore": before,
            "witness": witness,
            "localTruthAfter": before,
        }
        validate_json(result)
        return result
    branches = root / "branches"
    if branches.exists():
        for path in sorted(branches.glob("*.json")):
            path.unlink()
        branches.rmdir()
    _write_balance(root, cast(int, witness["balance"]))
    after = inspect_authority_truth(root)
    result = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1n-truth-restore-result",
        "truthRecoveryId": _TRUTH_RECOVERY_ID,
        "status": "restored",
        "worldMutated": True,
        "localTruthBefore": before,
        "witness": witness,
        "localTruthAfter": after,
    }
    validate_json(result)
    return result


def _fault_truth(root: Path, fault: str) -> None:
    canonical = _canonical_path(root)
    if fault == "missing":
        canonical.unlink(missing_ok=True)
    elif fault == "corrupt":
        _atomic_write(
            canonical,
            b'{"schemaVersion":1,"kind":"ordivon.security.c1n-private-balance","balance":',
        )
        canonical.chmod(0o600)
    elif fault == "fork":
        canonical.unlink(missing_ok=True)
        branches = root / "branches"
        branches.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            branches / "candidate-a.json", canonical_bytes(_balance_object(_DESIRED_BALANCE))
        )
        _atomic_write(
            branches / "candidate-b.json", canonical_bytes(_balance_object(_DUPLICATE_BALANCE))
        )
        (branches / "candidate-a.json").chmod(0o600)
        (branches / "candidate-b.json").chmod(0o600)
    else:
        raise ValueError(f"unsupported C1-N fault: {fault}")


def _prepare_fault_history(
    state_root: Path,
    witness_root: Path,
    *,
    fault: str,
    history: str,
    pre_fault_balance: int,
) -> JsonObject:
    lineage = f"lineage:c1n:{fault}:{history}"
    private_root = state_root / fault / history / "private"
    witness_path = witness_root / fault / f"{history}.json"
    _write_balance(private_root, pre_fault_balance)
    witness = _seal_witness(witness_path, balance=pre_fault_balance, lineage=lineage)
    pre_fault_tree = _tree_digest(private_root)
    _fault_truth(private_root, fault)
    post_fault_tree = _tree_digest(private_root)
    observation = inspect_authority_truth(private_root)
    ensure = apply_ensure_repaired(private_root)
    result: JsonObject = {
        "schemaVersion": 1,
        "fault": fault,
        "history": history,
        "lineage": lineage,
        "evaluatorOnlyPreFaultBalance": pre_fault_balance,
        "privateRoot": str(private_root),
        "witnessPath": str(witness_path),
        "witnessDigest": witness.get("witnessDigest"),
        "preFaultTreeDigest": pre_fault_tree,
        "postFaultTreeDigest": post_fault_tree,
        "postFaultObservation": observation,
        "ensureWithoutWitness": ensure,
        "postEnsureTreeDigest": _tree_digest(private_root),
    }
    validate_json(result)
    return result


def _path_from_history(history: JsonObject, key: str) -> Path:
    value = history.get(key)
    if not isinstance(value, str):
        raise ValueError(f"C1-N history lacks {key}")
    return Path(value)


def _recover_history(history: JsonObject) -> JsonObject:
    root = _path_from_history(history, "privateRoot")
    witness = _path_from_history(history, "witnessPath")
    lineage = history.get("lineage")
    if not isinstance(lineage, str):
        raise ValueError("C1-N history lacks lineage")
    restore = restore_truth_from_witness(root, witness, lineage=lineage)
    ensure = apply_ensure_repaired(root)
    result: JsonObject = {
        "restore": restore,
        "ensureAfterRestore": ensure,
        "finalTruth": inspect_authority_truth(root),
        "finalTreeDigest": _tree_digest(root),
    }
    validate_json(result)
    return result


def _supervisor(args: argparse.Namespace) -> None:
    revision = _git_revision(Path.cwd(), "Security")
    if args.state_root is None or args.receipt is None:
        raise ValueError("C1-N requires state-root and receipt")
    args.state_root.mkdir(parents=True, exist_ok=False)
    witness_root = args.state_root / "external-witness"
    histories: dict[str, dict[str, JsonObject]] = {}
    recoveries: dict[str, dict[str, JsonObject]] = {}
    for fault in ("missing", "corrupt", "fork"):
        repaired = _prepare_fault_history(
            args.state_root,
            witness_root,
            fault=fault,
            history="repaired",
            pre_fault_balance=_DESIRED_BALANCE,
        )
        unrepaired = _prepare_fault_history(
            args.state_root,
            witness_root,
            fault=fault,
            history="unrepaired",
            pre_fault_balance=_DUPLICATE_BALANCE,
        )
        histories[fault] = {"repaired": repaired, "unrepaired": unrepaired}

    # Prove one exact invalid witness cannot become a truth oracle.
    tamper_source = _path_from_history(histories["missing"]["unrepaired"], "witnessPath")
    tampered_path = witness_root / "tampered.json"
    tampered = bytearray(tamper_source.read_bytes())
    tampered[-2] = 48 if tampered[-2] != 48 else 49
    _atomic_write(tampered_path, bytes(tampered))
    tamper_root = args.state_root / "tampered-private"
    _write_balance(tamper_root, _DUPLICATE_BALANCE)
    _fault_truth(tamper_root, "missing")
    tamper_restore = restore_truth_from_witness(
        tamper_root,
        tampered_path,
        lineage=cast(str, histories["missing"]["unrepaired"]["lineage"]),
    )

    for fault, pair in histories.items():
        recoveries[fault] = {
            "repaired": _recover_history(pair["repaired"]),
            "unrepaired": _recover_history(pair["unrepaired"]),
        }

    gates: dict[str, bool] = {}
    expected_status = {"missing": "missing", "corrupt": "corrupt", "fork": "fork-conflict"}
    for fault, pair in histories.items():
        a = pair["repaired"]
        b = pair["unrepaired"]
        gates[f"{fault}HistoriesHadDifferentPreFaultTruth"] = (
            a["evaluatorOnlyPreFaultBalance"] == _DESIRED_BALANCE
            and b["evaluatorOnlyPreFaultBalance"] == _DUPLICATE_BALANCE
        )
        gates[f"{fault}PostFaultAuthorityViewsEquivalent"] = (
            a["postFaultObservation"] == b["postFaultObservation"]
            and cast(dict[str, object], a["postFaultObservation"])["status"]
            == expected_status[fault]
        )
        gates[f"{fault}EnsureFailsClosedWithoutTruth"] = all(
            cast(dict[str, object], item["ensureWithoutWitness"])["worldMutated"] is False
            and cast(dict[str, object], item["ensureWithoutWitness"])["treeDigestBefore"]
            == cast(dict[str, object], item["ensureWithoutWitness"])["treeDigestAfter"]
            for item in pair.values()
        )
        gates[f"{fault}WitnessRecoveryRestoresBothHistories"] = all(
            cast(dict[str, object], recoveries[fault][name]["restore"])["status"] == "restored"
            and cast(dict[str, object], recoveries[fault][name]["finalTruth"])["status"]
            == "healthy"
            and cast(dict[str, object], recoveries[fault][name]["finalTruth"])["balance"]
            == _DESIRED_BALANCE
            for name in ("repaired", "unrepaired")
        )
        gates[f"{fault}RecoveredEnsurePreservesSemanticDistinction"] = (
            cast(dict[str, object], recoveries[fault]["repaired"]["ensureAfterRestore"])["status"]
            == "already-repaired"
            and cast(dict[str, object], recoveries[fault]["unrepaired"]["ensureAfterRestore"])[
                "status"
            ]
            == "applied"
        )
    gates["tamperedWitnessFailsClosed"] = (
        tamper_restore.get("status") == "invalid-witness"
        and tamper_restore.get("worldMutated") is False
        and inspect_authority_truth(tamper_root).get("status") == "missing"
    )
    gates["sameC1MIdempotentCompensationIdentityPreserved"] = (
        _compensation_binding("idempotent")["compensationEffectId"]
        == "range-effect:c1m-idempotent-private-compensation-v1"
    )
    gates["witnessRecoveryHasDistinctIdentity"] = (
        _compensation_binding("idempotent")["compensationEffectId"] != _TRUTH_RECOVERY_ID
    )
    gates["noNetworkOrExternalTargetConsumed"] = True

    passed = all(gates.values())
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1n-downstream-truth-failure-acceptance",
        "status": "accepted" if passed else "failed",
        "securityRevision": revision,
        "compensationBinding": _compensation_binding("idempotent"),
        "truthRecoveryIdentity": _TRUTH_RECOVERY_ID,
        "histories": cast(JsonObject, histories),
        "recoveries": cast(JsonObject, recoveries),
        "tamperedWitness": {
            "witnessPath": str(tampered_path),
            "restore": tamper_restore,
            "finalTruth": inspect_authority_truth(tamper_root),
        },
        "gates": gates,
        "interpretation": {
            "idempotencyRequiresTrustworthyPredicateTruth": passed,
            "missingTruthSafeToGuess": False,
            "corruptTruthSafeToGuess": False,
            "forkedTruthSafeToGuess": False,
            "sealedExternalWitnessCanRestoreTruthInThisStaticFaultModel": passed,
            "witnessIntegrityRequired": True,
            "witnessFreshnessProved": False,
            "sharedAtomicBoundaryRequired": False,
            "genericTransactionManagerRequired": False,
        },
    }
    _write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if not passed:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run C1-N downstream truth failure and sealed-witness recovery acceptance."
    )
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--receipt", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    _supervisor(args)


if __name__ == "__main__":
    main()
