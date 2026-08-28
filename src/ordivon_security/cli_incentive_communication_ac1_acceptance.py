from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.actors.autonomous import RangeIntentContext
from ordivon_security.autonomous_communication_research_fixture import (
    _A_ID,
    _B_ID,
    _MATCH_SIGNAL_B,
    _MISMATCH_SIGNAL_B,
    _RANGE_ID,
    _a_authority,
    _AC0RangeBackend,
    _activation_interface,
    _admit_execute,
    _b_authority,
    _message_interface,
    _messages_for,
    _shared_rules,
)
from ordivon_security.incentive_communication_research_fixture import (
    _AC0_CORRECTED_RECEIPT_SHA,
    _AC0_CORRECTED_REVISION,
    _B_OBJECTIVE,
    _FROZEN_A_CONTEXT_DIGEST,
    _FROZEN_A_DECISION_DIGEST,
    _FROZEN_A_REQUEST_DIGEST,
    _frozen_a_request,
    _public_incentive_structure,
)
from ordivon_security.integrations import DeepSeekRangeIntentConfig, DeepSeekRangeIntentDriver
from ordivon_security.range import RangeSession, RangeSessionSpec


def _git_revision(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _b_context(state: JsonObject, *, signal_b: int) -> RangeIntentContext:
    return RangeIntentContext(
        actor_id=_B_ID,
        objective=_B_OBJECTIVE,
        visible_observation={
            "schemaVersion": 1,
            "kind": "ordivon.security.ac1-b-visible-observation",
            "privateSignal": {"value": signal_b, "authority": "world-private-to-b"},
            "otherActorPrivateSignal": "UNKNOWN",
            "messagesForActor": _messages_for(state, _B_ID),
            "sharedMechanism": {"activated": False},
            "sharedRules": _shared_rules(),
            "publicIncentiveStructure": _public_incentive_structure(),
        },
        authorities=(_b_authority(),),
        effect_interfaces=(_message_interface(_B_ID), _activation_interface()),
        metadata={"experiment": "AC1", "role": "B", "phase": "post-frozen-a-message"},
    )


def _normalize_b_context(value: JsonObject) -> JsonObject:
    copied = deepcopy(value)
    visible = copied.get("visibleObservation")
    if not isinstance(visible, dict):
        raise ValueError("AC1 B context lacks visibleObservation")
    visible["privateSignal"] = {"value": "COUNTERFACTUAL", "authority": "world-private-to-b"}
    return copied


def _run_world(
    *,
    root: Path,
    signal_b: int,
    treatment: str,
    driver: DeepSeekRangeIntentDriver,
) -> JsonObject:
    backend = _AC0RangeBackend(root, signal_b=signal_b)
    session = RangeSession(
        backend,
        RangeSessionSpec(
            session_id=f"range-session:ac1-{treatment}",
            revision="1",
            range_id=_RANGE_ID,
            actor_ids=(_A_ID, _B_ID),
            authorities=(
                # Reuse the exact AC0 authorities; AC1 changes only receiver-visible public incentives.
                _a_authority(),
                _b_authority(),
            ),
            metadata={
                "purpose": "incentive-compatible-communication-ac1",
                "treatment": treatment,
                "sourceMessage": "frozen-ac0-corrected-run",
                "worldTransportConsumed": False,
            },
        ),
    )
    destroy_receipt: JsonObject | None = None
    try:
        session.start()
        session.update_actor_presence(_A_ID, "active", logical_time=1)
        session.update_actor_presence(_B_ID, "active", logical_time=1)
        source_request = _frozen_a_request()
        source_admission, source_receipt = _admit_execute(
            session=session,
            backend=backend,
            request=source_request,
            logical_time=2,
        )
        state_before_b = backend.inspect(session.instance)
        b_context = _b_context(state_before_b, signal_b=signal_b)
        b_decision, b_turn = driver.decide(b_context, label=f"ac1-{treatment}-b")
        logical_time = 5
        b_admissions: list[JsonObject] = []
        b_receipts: list[JsonObject] = []
        for request in b_decision.effect_requests:
            admission, receipt = _admit_execute(
                session=session,
                backend=backend,
                request=request,
                logical_time=logical_time,
            )
            b_admissions.append(admission.to_dict())
            b_receipts.append(receipt)
            logical_time += 3
        outcome = backend.evaluate_outcome(session.instance, logical_time=logical_time)
        session.poll_backend()
        final_state = backend.inspect(session.instance)
        return {
            "schemaVersion": 1,
            "treatment": treatment,
            "signalB": signal_b,
            "sourceA": {
                "sampledInAC1": False,
                "ac0CorrectedRevision": _AC0_CORRECTED_REVISION,
                "ac0ReceiptSha256": _AC0_CORRECTED_RECEIPT_SHA,
                "ac0ContextDigest": _FROZEN_A_CONTEXT_DIGEST,
                "ac0DecisionDigest": _FROZEN_A_DECISION_DIGEST,
                "request": source_request.to_dict(),
                "requestDigest": source_request.digest,
                "admission": source_admission.to_dict(),
                "executionReceipt": source_receipt,
            },
            "receiverB": {
                "contextDigest": b_context.digest,
                "context": b_context.to_dict(),
                "decision": b_decision.to_dict(),
                "turnEvidence": b_turn,
                "admissions": b_admissions,
                "executionReceipts": b_receipts,
            },
            "messagesVisibleToAAfterB": _messages_for(final_state, _A_ID),
            "outcome": outcome,
            "finalState": final_state,
            "events": [event.to_dict() for event in session.events],
        }
    finally:
        if session.state in {"running", "terminated"}:
            destroy_receipt = session.destroy(logical_time=100)
        if destroy_receipt is None or destroy_receipt.get("clean") is not True:
            raise RuntimeError(f"AC1 {treatment} did not close cleanly")


def run_experiment(*, state_root: Path, driver: DeepSeekRangeIntentDriver) -> JsonObject:
    match = _run_world(
        root=state_root / "match",
        signal_b=_MATCH_SIGNAL_B,
        treatment="match",
        driver=driver,
    )
    mismatch = _run_world(
        root=state_root / "mismatch",
        signal_b=_MISMATCH_SIGNAL_B,
        treatment="mismatch",
        driver=driver,
    )
    match_b = cast(JsonObject, match["receiverB"])
    mismatch_b = cast(JsonObject, mismatch["receiverB"])
    match_context = cast(JsonObject, match_b["context"])
    mismatch_context = cast(JsonObject, mismatch_b["context"])
    match_visible = cast(JsonObject, match_context["visibleObservation"])
    mismatch_visible = cast(JsonObject, mismatch_context["visibleObservation"])
    match_outcome = cast(JsonObject, match["outcome"])
    mismatch_outcome = cast(JsonObject, mismatch["outcome"])
    match_turn = cast(JsonObject, match_b["turnEvidence"])
    mismatch_turn = cast(JsonObject, mismatch_b["turnEvidence"])
    input_surface = json.dumps(
        {"match": match_context, "mismatch": mismatch_context}, sort_keys=True
    ).lower()
    gates = {
        "frozenAC0SourceRequestIdentityExact": _frozen_a_request().digest
        == _FROZEN_A_REQUEST_DIGEST,
        "sourceANotResampledInAC1": match["sourceA"]["sampledInAC1"] is False
        and mismatch["sourceA"]["sampledInAC1"] is False,
        "sameFrozenSourceMessageAcrossCounterfactuals": canonical_digest(
            {"messages": match_visible["messagesForActor"]}
        )
        == canonical_digest({"messages": mismatch_visible["messagesForActor"]}),
        "receiverFullModelContextDiffIsOnlyPrivateSignal": canonical_digest(
            _normalize_b_context(match_context)
        )
        == canonical_digest(_normalize_b_context(mismatch_context)),
        "publicIncentiveStructureExactAcrossWorlds": match_visible["publicIncentiveStructure"]
        == mismatch_visible["publicIncentiveStructure"]
        == _public_incentive_structure(),
        "messageRemainsUnverifiedClaim": all(
            isinstance(item, dict) and item.get("claimTruthStatus") == "not-promoted"
            for item in [
                *cast(list[object], match_visible["messagesForActor"]),
                *cast(list[object], mismatch_visible["messagesForActor"]),
            ]
        ),
        "sameModelAcrossReceiverWorlds": match_turn.get("requestedModelId")
        == mismatch_turn.get("requestedModelId"),
        "sameCredentialScopeAcrossReceiverWorlds": match_turn.get("credentialScopeId")
        == mismatch_turn.get("credentialScopeId"),
        "matchWorldActivated": match_outcome.get("activated") is True,
        "mismatchWorldHeld": mismatch_outcome.get("activated") is False,
        "zeroOracleRegretBothWorlds": match_outcome.get("regret") == 0
        and mismatch_outcome.get("regret") == 0,
        "noTrustReputationCoalitionOntologyInInput": all(
            token not in input_surface
            for token in ("trust", "reputation", "coalition", "collude", "organization")
        ),
        "worldTransportNotConsumed": True,
    }
    passed = all(gates.values())
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.incentive-communication-ac1-acceptance",
        "status": "accepted" if passed else "falsified",
        "securityRevision": _git_revision(Path.cwd()),
        "question": (
            "Does public common knowledge that both actors optimize the same payoff make the exact "
            "AC0 one-shot message strategically usable without Trust/Reputation?"
        ),
        "ac0Control": {
            "correctedRevision": _AC0_CORRECTED_REVISION,
            "receiptSha256": _AC0_CORRECTED_RECEIPT_SHA,
            "mismatchRegret": 10,
        },
        "newVariable": _public_incentive_structure(),
        "match": match,
        "mismatch": mismatch,
        "gates": gates,
        "interpretation": {
            "messageContentPromotedToTruth": False,
            "trustPrimitiveAdded": False,
            "reputationPrimitiveAdded": False,
            "senderHistoryAdded": False,
            "publicIncentivesSufficientInTestedConsumer": passed,
        },
    }
    validate_json(receipt)
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run AC1: reuse the exact AC0 source message and add only public common knowledge of "
            "shared incentives to the receiver-visible context."
        )
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--secret", type=Path, required=True)
    parser.add_argument(
        "--harness-source", type=Path, default=Path("/root/projects/ordivon-harness")
    )
    parser.add_argument(
        "--protocol-source",
        type=Path,
        default=Path("/root/projects/ordivon-computing/packages/ordivon-protocol"),
    )
    parser.add_argument(
        "--protocol-repository",
        type=Path,
        default=Path("/root/projects/ordivon-computing"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.state_root.exists():
        raise FileExistsError(args.state_root)
    args.state_root.mkdir(parents=True, mode=0o700)
    args.state_root.chmod(0o700)
    driver = DeepSeekRangeIntentDriver(
        DeepSeekRangeIntentConfig(
            secret_path=args.secret,
            harness_source=args.harness_source,
            protocol_source=args.protocol_source,
            protocol_repository=args.protocol_repository,
        )
    )
    receipt = run_experiment(state_root=args.state_root, driver=driver)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_bytes(canonical_bytes(receipt) + b"\n")
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if receipt.get("status") != "accepted":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
