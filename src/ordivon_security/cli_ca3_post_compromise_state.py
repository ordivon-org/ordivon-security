from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_NODES = ("a", "b", "c")
_TOKENS = {
    "a": "ca3-token-a-v1",
    "b": "ca3-token-b-v1",
    "c": "ca3-token-c-v1",
}


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"CA3 state is not an object: {path}")
    return value


def _node(root: Path, node_id: str) -> Path:
    if node_id not in _NODES:
        raise ValueError(f"unknown CA3 node: {node_id}")
    path = (root / "nodes" / node_id).resolve()
    if root.resolve() not in path.parents:
        raise ValueError("CA3 node escaped owned world root")
    return path


def _authority_path(root: Path, node_id: str) -> Path:
    return _node(root, node_id) / "authority.json"


def _issue_token(root: Path, node_id: str, token: str, generation: int) -> None:
    _write_json(
        _authority_path(root, node_id),
        {
            "node": node_id,
            "generation": generation,
            "tokenDigest": _digest_text(token),
            "revoked": False,
        },
    )


def _revoke(root: Path, node_id: str) -> None:
    path = _authority_path(root, node_id)
    authority = _read_json(path)
    authority["revoked"] = True
    authority["generation"] = int(authority["generation"]) + 1
    _write_json(path, authority)


def _authorized(root: Path, node_id: str, token: str) -> tuple[bool, dict[str, Any]]:
    authority = _read_json(_authority_path(root, node_id))
    return (
        authority.get("revoked") is False
        and authority.get("tokenDigest") == _digest_text(token),
        authority,
    )


def _worker_control(root: Path, node_id: str, token: str, source: str) -> dict[str, Any]:
    allowed, authority = _authorized(root, node_id, token)
    receipt = {
        "operation": "control",
        "node": node_id,
        "source": source,
        "authorityGeneration": authority["generation"],
        "authorized": allowed,
        "worldTruthVerified": False,
    }
    if allowed:
        _write_json(
            _node(root, node_id) / "current-control.json",
            {
                "node": node_id,
                "source": source,
                "authorityGeneration": authority["generation"],
                "controlEstablished": True,
            },
        )
    return receipt


def _worker_persist(root: Path, node_id: str, token: str) -> dict[str, Any]:
    allowed, authority = _authorized(root, node_id, token)
    receipt = {
        "operation": "persist",
        "node": node_id,
        "authorityGeneration": authority["generation"],
        "authorized": allowed,
        "worldTruthVerified": False,
    }
    if allowed:
        _write_json(
            _node(root, node_id) / "persistence.json",
            {
                "node": node_id,
                "effectId": "ca3-benign-startup-v1",
                "authorityGenerationAtCreation": authority["generation"],
            },
        )
    return receipt


def _worker_restart(root: Path, node_id: str) -> dict[str, Any]:
    persistence = _node(root, node_id) / "persistence.json"
    activated = persistence.is_file()
    if activated:
        _write_json(
            _node(root, node_id) / "service-live.json",
            {"node": node_id, "effectId": "ca3-benign-startup-v1", "live": True},
        )
    return {
        "operation": "restart",
        "node": node_id,
        "persistenceObserved": persistence.is_file(),
        "serviceActivated": activated,
        "worldTruthVerified": False,
    }


def _worker_reconnect(root: Path, node_id: str, token: str) -> dict[str, Any]:
    service_live = (_node(root, node_id) / "service-live.json").is_file()
    allowed, authority = _authorized(root, node_id, token)
    usable = service_live and allowed
    if usable:
        _write_json(
            _node(root, node_id) / "current-control.json",
            {
                "node": node_id,
                "source": "reconnect",
                "authorityGeneration": authority["generation"],
                "controlEstablished": True,
            },
        )
    return {
        "operation": "reconnect",
        "node": node_id,
        "serviceLive": service_live,
        "authorityGeneration": authority["generation"],
        "authorized": allowed,
        "usableControl": usable,
        "worldTruthVerified": False,
    }


def _worker_delegate(root: Path, node_id: str, token: str) -> dict[str, Any]:
    allowed, authority = _authorized(root, node_id, token)
    delegation_path = _node(root, node_id) / "delegation.json"
    receipt: dict[str, Any] = {
        "operation": "delegate-once",
        "node": node_id,
        "authorityGeneration": authority["generation"],
        "authorized": allowed,
        "delegationPresent": delegation_path.is_file(),
        "childAttempted": False,
        "childExitCode": None,
        "worldTruthVerified": False,
    }
    if not allowed or not delegation_path.is_file():
        return receipt
    delegation = _read_json(delegation_path)
    if delegation.get("source") != node_id or delegation.get("target") not in _NODES:
        return receipt
    target = str(delegation["target"])
    child = subprocess.run(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_ca3_post_compromise_state",
            "--worker",
            "control",
            "--root",
            str(root),
            "--node",
            target,
            "--token",
            str(delegation["targetToken"]),
            "--source",
            f"delegated-from:{node_id}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )
    receipt["childAttempted"] = True
    receipt["childExitCode"] = child.returncode
    if child.stdout.strip():
        child_receipt = json.loads(child.stdout)
        receipt["childAuthorized"] = bool(child_receipt.get("authorized"))
    return receipt


def _world_truth(root: Path) -> dict[str, Any]:
    truth: dict[str, Any] = {"nodes": {}}
    for node_id in _NODES:
        node = _node(root, node_id)
        authority = _read_json(_authority_path(root, node_id))
        control_path = node / "current-control.json"
        control = _read_json(control_path) if control_path.is_file() else None
        truth["nodes"][node_id] = {
            "authorityGeneration": authority["generation"],
            "credentialRevoked": authority["revoked"],
            "persistencePresent": (node / "persistence.json").is_file(),
            "serviceLive": (node / "service-live.json").is_file(),
            "currentControl": control is not None,
            "currentControlSource": control.get("source") if control is not None else None,
            "delegationPresent": (node / "delegation.json").is_file(),
        }
    return truth


def _eradicate(root: Path, node_id: str) -> dict[str, Any]:
    node = _node(root, node_id)
    removed: list[str] = []
    for name in ("persistence.json", "service-live.json", "current-control.json", "delegation.json"):
        path = node / name
        if path.exists():
            path.unlink()
            removed.append(name)
    _revoke(root, node_id)
    return {"node": node_id, "removed": removed, "authorityRevoked": True}


def _run_worker(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    if args.worker == "control":
        result = _worker_control(root, args.node, args.token, args.source)
    elif args.worker == "persist":
        result = _worker_persist(root, args.node, args.token)
    elif args.worker == "restart":
        result = _worker_restart(root, args.node)
    elif args.worker == "reconnect":
        result = _worker_reconnect(root, args.node, args.token)
    elif args.worker == "delegate-once":
        result = _worker_delegate(root, args.node, args.token)
    else:
        raise ValueError(f"unsupported CA3 worker operation: {args.worker}")
    print(json.dumps(result, sort_keys=True))
    return 0 if bool(result.get("authorized", True)) else 3


def _invoke_worker(
    root: Path,
    operation: str,
    node_id: str,
    *,
    token: str | None = None,
    source: str = "controller",
) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "ordivon_security.cli_ca3_post_compromise_state",
        "--worker",
        operation,
        "--root",
        str(root),
        "--node",
        node_id,
        "--source",
        source,
    ]
    if token is not None:
        command.extend(["--token", token])
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    receipt = json.loads(completed.stdout) if completed.stdout.strip() else {}
    receipt["processExitCode"] = completed.returncode
    receipt["stderrSha256"] = _digest_text(completed.stderr)
    return receipt


def _reset_runtime_state(root: Path, node_id: str) -> None:
    node = _node(root, node_id)
    for name in ("current-control.json", "service-live.json", "delegation.json"):
        path = node / name
        if path.exists():
            path.unlink()


def _run_experiment(output: Path | None) -> int:
    with tempfile.TemporaryDirectory(prefix="ordivon-ca3-") as raw_root:
        root = Path(raw_root).resolve()
        for node_id in _NODES:
            _node(root, node_id).mkdir(parents=True)
            _issue_token(root, node_id, _TOKENS[node_id], generation=1)

        events: list[dict[str, Any]] = []

        # Establish initial control on A and one persistence artifact.
        events.append({"step": "control-a", "receipt": _invoke_worker(root, "control", "a", token=_TOKENS["a"]), "truth": _world_truth(root)})
        events.append({"step": "persist-a", "receipt": _invoke_worker(root, "persist", "a", token=_TOKENS["a"]), "truth": _world_truth(root)})
        _reset_runtime_state(root, "a")
        restart_a = _invoke_worker(root, "restart", "a")
        _revoke(root, "a")
        stale_reconnect_a = _invoke_worker(root, "reconnect", "a", token=_TOKENS["a"])
        truth_persist_no_control = _world_truth(root)
        events.append({"step": "restart-revoke-reconnect-a", "restartReceipt": restart_a, "reconnectReceipt": stale_reconnect_a, "truth": truth_persist_no_control})

        # Credential-authorized movement to B, then exact revocation negative.
        move_b = _invoke_worker(root, "control", "b", token=_TOKENS["b"], source="controller-move")
        truth_move_b = _world_truth(root)
        _revoke(root, "b")
        (_node(root, "b") / "current-control.json").unlink(missing_ok=True)
        stale_move_b = _invoke_worker(root, "control", "b", token=_TOKENS["b"], source="stale-controller")
        truth_revoked_b = _world_truth(root)
        events.append({"step": "credential-movement-b", "validReceipt": move_b, "validTruth": truth_move_b, "revokedReceipt": stale_move_b, "revokedTruth": truth_revoked_b})

        # Restore B/C synthetic authority for two equivalent propagation treatments.
        _issue_token(root, "b", "ca3-token-b-v2", generation=3)
        _issue_token(root, "c", "ca3-token-c-v2", generation=2)
        token_b_v2 = "ca3-token-b-v2"
        token_c_v2 = "ca3-token-c-v2"
        _reset_runtime_state(root, "b")
        _reset_runtime_state(root, "c")

        controller_directed_receipts = [
            _invoke_worker(root, "control", "b", token=token_b_v2, source="controller-propagation"),
            _invoke_worker(root, "control", "c", token=token_c_v2, source="controller-propagation"),
        ]
        direct_truth = _world_truth(root)

        _reset_runtime_state(root, "b")
        _reset_runtime_state(root, "c")
        _write_json(
            _node(root, "b") / "delegation.json",
            {
                "source": "b",
                "target": "c",
                "targetToken": token_c_v2,
                "maxChildren": 1,
                "mode": "single-hop-test-only",
            },
        )
        delegated_b_control = _invoke_worker(root, "control", "b", token=token_b_v2, source="controller-delegation-seed")
        delegated_once = _invoke_worker(root, "delegate-once", "b", token=token_b_v2, source="controller")
        delegated_truth = _world_truth(root)
        delegated_contract = _read_json(_node(root, "b") / "delegation.json")
        events.append({
            "step": "propagation-control-mode",
            "controllerDirected": {
                "controllerSelectedTargetControls": 2,
                "controllerSelectedTargets": ["b", "c"],
                "receipts": controller_directed_receipts,
                "truth": direct_truth,
            },
            "delegated": {
                "controllerSelectedTargetControls": 1,
                "controllerSelectedTargets": ["b"],
                "delegationActivations": 1,
                "seedControlReceipt": delegated_b_control,
                "delegateReceipt": delegated_once,
                "truth": delegated_truth,
            },
        })

        # Blue-like eradication and stale-belief negatives.
        eradication = [_eradicate(root, node_id) for node_id in _NODES]
        stale_attempts = {
            "a": _invoke_worker(root, "control", "a", token=_TOKENS["a"], source="stale-after-eradication"),
            "b": _invoke_worker(root, "control", "b", token=token_b_v2, source="stale-after-eradication"),
            "c": _invoke_worker(root, "control", "c", token=token_c_v2, source="stale-after-eradication"),
        }
        final_truth = _world_truth(root)

        gates = {
            "persistenceArtifactSurvivesRestart": truth_persist_no_control["nodes"]["a"]["persistencePresent"] is True,
            "persistenceServiceCanBeLiveWithoutUsableControl": (
                truth_persist_no_control["nodes"]["a"]["serviceLive"] is True
                and truth_persist_no_control["nodes"]["a"]["currentControl"] is False
                and stale_reconnect_a.get("usableControl") is False
            ),
            "validCredentialMovesToB": move_b.get("authorized") is True and truth_move_b["nodes"]["b"]["currentControl"] is True,
            "revokedCredentialBlocksSameMovement": stale_move_b.get("authorized") is False and truth_revoked_b["nodes"]["b"]["currentControl"] is False,
            "controllerDirectedReachesBAndC": direct_truth["nodes"]["b"]["currentControl"] is True and direct_truth["nodes"]["c"]["currentControl"] is True,
            "delegatedContinuationReachesC": (
                delegated_once.get("childAttempted") is True
                and delegated_once.get("childAuthorized") is True
                and delegated_truth["nodes"]["c"]["currentControl"] is True
            ),
            "controllerSelectsCOnlyInDirectedTreatment": (
                direct_truth["nodes"]["c"]["currentControlSource"] == "controller-propagation"
                and delegated_truth["nodes"]["c"]["currentControlSource"] == "delegated-from:b"
            ),
            "delegatedContinuationIsBounded": (
                delegated_truth["nodes"]["b"]["delegationPresent"] is True
                and delegated_contract.get("maxChildren") == 1
                and delegated_contract.get("mode") == "single-hop-test-only"
            ),
            "eradicationRevokesAllAndRemovesCurrentControl": all(
                final_truth["nodes"][node_id]["credentialRevoked"] is True
                and final_truth["nodes"][node_id]["persistencePresent"] is False
                and final_truth["nodes"][node_id]["serviceLive"] is False
                and final_truth["nodes"][node_id]["currentControl"] is False
                for node_id in _NODES
            ),
            "staleBeliefActionsFailAfterEradication": all(
                receipt.get("authorized") is False for receipt in stale_attempts.values()
            ),
        }

        payload = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ca3-post-compromise-state",
            "authority": {
                "ownedLocalWorld": True,
                "syntheticCredentialsOnly": True,
                "networkUsed": False,
                "externalTargets": False,
                "delegationMaxChildren": 1,
            },
            "relationsUnderTest": ["CONTROL", "AUTHORITY", "CONTINUITY", "REACHABILITY"],
            "events": events,
            "eradication": eradication,
            "staleAttempts": stale_attempts,
            "finalTruth": final_truth,
            "gates": gates,
            "interpretation": {
                "persistenceBoundary": "persistent artifact/service presence does not imply currently usable controller control after authority revocation",
                "credentialBoundary": "credential possession is only useful while the current target authority generation accepts it",
                "movementBoundary": "a second foothold is a verified target control consequence, not merely possession of a credential or a controller request",
                "propagationBoundary": "controller-directed repeated movement and delegated continuation can reach the same bounded target but differ in where the next action is selected/executed",
                "eradicationBoundary": "fresh world truth after revocation/cleanup overrides stale controller belief and blocks old capability use",
                "nonClaim": "no credential stealing, malware, unrestricted lateral movement, network worm, third-party target, or reusable propagation engine is implemented",
            },
        }
        encoded = json.dumps(payload, sort_keys=True, indent=2) + "\n"
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if all(gates.values()) else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the bounded CA3 post-compromise state experiment.")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", choices=("control", "persist", "restart", "reconnect", "delegate-once"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--node", choices=_NODES)
    parser.add_argument("--token", default="")
    parser.add_argument("--source", default="controller")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.worker is not None:
        if args.root is None or args.node is None:
            raise SystemExit("--root and --node are required for CA3 worker mode")
        raise SystemExit(_run_worker(args))
    raise SystemExit(_run_experiment(args.output))


if __name__ == "__main__":
    main()
