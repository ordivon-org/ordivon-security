from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.autonomous_communication_research_fixture import (
    _A_ID,
    _ACTIVATE_EFFECT,
    _B_ID,
    _MATCH_SIGNAL_B,
    _MESSAGE_EFFECT,
    _MISMATCH_SIGNAL_B,
    _RANGE_ID,
    _a_authority,
    _a_context,
    _AC0RangeBackend,
    _admit_execute,
    _b_authority,
    _b_context,
    _git_revision,
    _messages_for,
)
from ordivon_security.integrations import DeepSeekRangeIntentConfig, DeepSeekRangeIntentDriver
from ordivon_security.range import (
    RangeEffectRequest,
    RangeSession,
    RangeSessionSpec,
)


def _run_world(
    *,
    root: Path,
    signal_b: int,
    treatment: str,
    source_decision_requests: tuple[RangeEffectRequest, ...],
    source_context_digest: str,
    source_decision_digest: str,
    source_turn: JsonObject,
    driver: DeepSeekRangeIntentDriver,
) -> JsonObject:
    backend = _AC0RangeBackend(root, signal_b=signal_b)
    session = RangeSession(
        backend,
        RangeSessionSpec(
            session_id=f"range-session:ac0-{treatment}",
            revision="1",
            range_id=_RANGE_ID,
            actor_ids=(_A_ID, _B_ID),
            authorities=(_a_authority(), _b_authority()),
            metadata={
                "purpose": "autonomous-communication-ac0",
                "treatment": treatment,
                "worldTransportConsumed": False,
            },
        ),
    )
    destroy_receipt: JsonObject | None = None
    try:
        session.start()
        session.update_actor_presence(_A_ID, "active", logical_time=1)
        session.update_actor_presence(_B_ID, "active", logical_time=1)
        logical_time = 2
        a_admissions: list[JsonObject] = []
        a_receipts: list[JsonObject] = []
        for request in source_decision_requests:
            admission, receipt = _admit_execute(
                session=session,
                backend=backend,
                request=request,
                logical_time=logical_time,
            )
            a_admissions.append(admission.to_dict())
            a_receipts.append(receipt)
            logical_time += 3

        state_before_b = backend.inspect(session.instance)
        b_context = _b_context(state_before_b, signal_b=signal_b)
        b_decision, b_turn = driver.decide(b_context, label=f"ac0-{treatment}-b")
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
        result: JsonObject = {
            "schemaVersion": 1,
            "treatment": treatment,
            "signalB": signal_b,
            "sourceA": {
                "contextDigest": source_context_digest,
                "decisionDigest": source_decision_digest,
                "turnEvidence": source_turn,
                "appliedRequests": [request.to_dict() for request in source_decision_requests],
                "admissions": a_admissions,
                "executionReceipts": a_receipts,
            },
            "receiverB": {
                "contextDigest": b_context.digest,
                "context": b_context.to_dict(),
                "visibleObservation": b_context.visible_observation,
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
        return result
    finally:
        if session.state in {"running", "terminated"}:
            destroy_receipt = session.destroy(logical_time=100)
        if destroy_receipt is None or destroy_receipt.get("clean") is not True:
            raise RuntimeError(f"AC0 {treatment} did not close cleanly")


def _projection_without_private_signal(value: JsonObject) -> JsonObject:
    copied = deepcopy(value)
    copied["privateSignal"] = {"value": "COUNTERFACTUAL", "authority": "world-private-to-b"}
    return copied


def _normalize_b_context(value: JsonObject) -> JsonObject:
    copied = deepcopy(value)
    visible = copied.get("visibleObservation")
    if not isinstance(visible, dict):
        raise ValueError("AC0 B context lacks visibleObservation")
    visible["privateSignal"] = {"value": "COUNTERFACTUAL", "authority": "world-private-to-b"}
    return copied


def run_experiment(*, state_root: Path, driver: DeepSeekRangeIntentDriver) -> JsonObject:
    a_context = _a_context()
    a_decision, a_turn = driver.decide(a_context, label="ac0-shared-a")
    source_requests = a_decision.effect_requests

    match = _run_world(
        root=state_root / "match",
        signal_b=_MATCH_SIGNAL_B,
        treatment="match",
        source_decision_requests=source_requests,
        source_context_digest=a_context.digest,
        source_decision_digest=a_decision.digest,
        source_turn=a_turn,
        driver=driver,
    )
    mismatch = _run_world(
        root=state_root / "mismatch",
        signal_b=_MISMATCH_SIGNAL_B,
        treatment="mismatch",
        source_decision_requests=source_requests,
        source_context_digest=a_context.digest,
        source_decision_digest=a_decision.digest,
        source_turn=a_turn,
        driver=driver,
    )

    match_b = cast(JsonObject, match["receiverB"])
    mismatch_b = cast(JsonObject, mismatch["receiverB"])
    match_visible = cast(JsonObject, match_b["visibleObservation"])
    mismatch_visible = cast(JsonObject, mismatch_b["visibleObservation"])
    match_messages = cast(list[object], match_visible["messagesForActor"])
    mismatch_messages = cast(list[object], mismatch_visible["messagesForActor"])
    match_outcome = cast(JsonObject, match["outcome"])
    mismatch_outcome = cast(JsonObject, mismatch["outcome"])

    forbidden_projection_keys = {
        "requestId",
        "requestDigest",
        "contextDigest",
        "decisionDigest",
        "eventId",
        "causalParents",
        "authorityDigest",
    }
    message_projection_keys_ok = all(
        isinstance(item, dict)
        and set(item) == {"messageId", "sourceId", "recipientId", "content", "claimTruthStatus"}
        and not (set(item) & forbidden_projection_keys)
        for item in [*match_messages, *mismatch_messages]
    )
    social_text = json.dumps(
        {
            "a": a_context.to_dict(),
            "matchB": cast(JsonObject, match_b["context"]),
            "mismatchB": cast(JsonObject, mismatch_b["context"]),
        },
        sort_keys=True,
    ).lower()
    gates = {
        "sourceAHasSingleSharedContext": match["sourceA"]["contextDigest"]
        == mismatch["sourceA"]["contextDigest"]
        == a_context.digest,
        "sourceAHasSingleSharedDecision": match["sourceA"]["decisionDigest"]
        == mismatch["sourceA"]["decisionDigest"]
        == a_decision.digest,
        "sourceACommunicated": len(source_requests) > 0
        and all(request.effect_type == _MESSAGE_EFFECT for request in source_requests),
        "sameSourceMessageProjectionAcrossCounterfactuals": canonical_digest(
            {"messages": match_messages}
        )
        == canonical_digest({"messages": mismatch_messages}),
        "receiverProjectionDiffIsOnlyPrivateSignal": canonical_digest(
            _projection_without_private_signal(match_visible)
        )
        == canonical_digest(_projection_without_private_signal(mismatch_visible)),
        "receiverFullModelContextDiffIsOnlyPrivateSignal": canonical_digest(
            _normalize_b_context(cast(JsonObject, match_b["context"]))
        )
        == canonical_digest(_normalize_b_context(cast(JsonObject, mismatch_b["context"]))),
        "receiverMessageProjectionExcludesExecutionProvenance": message_projection_keys_ok,
        "messagesRemainUnverifiedClaims": all(
            isinstance(item, dict) and item.get("claimTruthStatus") == "not-promoted"
            for item in [*match_messages, *mismatch_messages]
        ),
        "matchWorldActivated": match_outcome.get("activated") is True,
        "mismatchWorldHeld": mismatch_outcome.get("activated") is False,
        "zeroOracleRegretBothWorlds": match_outcome.get("regret") == 0
        and mismatch_outcome.get("regret") == 0,
        "receiverCanReplyWithoutReplyBeingRequired": all(
            interface.effect_type in {_MESSAGE_EFFECT, _ACTIVATE_EFFECT}
            for interface in _b_context(
                cast(JsonObject, match["finalState"]), signal_b=_MATCH_SIGNAL_B
            ).effect_interfaces
        ),
        "noTrustReputationCoalitionOntologyInAgentSurface": all(
            token not in social_text
            for token in ("trust", "reputation", "coalition", "collude", "organization")
        ),
        "worldTransportNotConsumed": True,
    }
    passed = all(gates.values())
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.autonomous-communication-ac0-acceptance",
        "status": "accepted" if passed else "falsified",
        "securityRevision": _git_revision(Path.cwd()),
        "question": (
            "Can two autonomous Agents coordinate one bounded shared consequence through ordinary "
            "claim messages plus actor-specific visible-state projection, without a mailbox, Trust, "
            "Reputation, coalition, or communication core?"
        ),
        "sourceA": {
            "contextDigest": a_context.digest,
            "decisionDigest": a_decision.digest,
            "decision": a_decision.to_dict(),
            "turnEvidence": a_turn,
        },
        "match": match,
        "mismatch": mismatch,
        "gates": gates,
        "interpretation": {
            "messageDeliveryEqualsRecipientKnowledge": False,
            "messageContentEqualsWorldTruth": False,
            "actorSpecificProjectionExperimentLocal": True,
            "genericMailboxRequired": False if passed else None,
            "rangeEventVisibilityOntologyRequired": False if passed else None,
            "trustOrReputationRequired": False if passed else None,
            "coordinationObservedWithoutCoalitionPrimitive": passed,
        },
    }
    validate_json(receipt)
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run AC0: two autonomous Agents coordinate one bounded shared consequence through "
            "ordinary unverified messages and actor-specific visible-state projection."
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
