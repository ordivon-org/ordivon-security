from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.actors.autonomous import RangeIntentContext
from ordivon_security.cli_autonomous_communication_ac0_acceptance import (
    _A_ID,
    _B_ID,
    _MATCH_SIGNAL_B,
    _MESSAGE_EFFECT,
    _MISMATCH_SIGNAL_B,
    _RANGE_ID,
    _AC0RangeBackend,
    _a_authority,
    _activation_interface,
    _b_authority,
    _message_interface,
    _messages_for,
    _shared_rules,
)
from ordivon_security.cli_incentive_communication_ac1_acceptance import (
    _B_OBJECTIVE,
    _FROZEN_A_CONTEXT_DIGEST,
    _FROZEN_A_DECISION_DIGEST,
    _FROZEN_A_REQUEST_DIGEST,
    _frozen_a_request,
    _public_incentive_structure,
)
from ordivon_security.integrations import (
    DeepSeekRangeIntentConfig,
    DeepSeekRangeIntentDriver,
    RangeIntentHarnessFailure,
)
from ordivon_security.range import (
    PendingRangeEvent,
    RangeAuthority,
    RangeEffectAdmission,
    RangeEffectRequest,
    RangeSession,
    RangeSessionInstance,
    RangeSessionSpec,
)

_DISCLOSURE_AUTHORITY = "range-authority:ac2-a-disclosure"
_DISCLOSURE_ZONE = "zone:ac2-private-signal"
_DISCLOSURE_CAPABILITY = "signal.disclose-verified"
_DISCLOSURE_EFFECT = "signal.publish-verified"
_DISCLOSURE_REQUEST_ID = "range-effect-request:ac2-controlled-disclosure-a-to-b"
_DISCLOSURE_ID = "verified-disclosure:ac2:a-signal:1"
_AC0_RECEIPT_SHA = "sha256:3c269a616c7723c6c015077860f023cdadcab88c2967680b3615628a68bccaad"
_AC1_RECEIPT_SHA = "sha256:4165f48486b393db7b5ce52edda4e2adbaa0568c79dcb70339edb1af63eb3e83"


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


def _disclosure_authority() -> RangeAuthority:
    return RangeAuthority(
        authority_id=_DISCLOSURE_AUTHORITY,
        revision="1",
        actor_id=_A_ID,
        zone_refs=(_DISCLOSURE_ZONE,),
        capabilities=(_DISCLOSURE_CAPABILITY,),
        external_boundary="owned-local-ac2-world",
        metadata={
            "role": "controlled-selective-disclosure",
            "autonomousChoiceTested": False,
        },
    )


def _controlled_disclosure_request() -> RangeEffectRequest:
    return RangeEffectRequest(
        request_id=_DISCLOSURE_REQUEST_ID,
        actor_id=_A_ID,
        authority_id=_DISCLOSURE_AUTHORITY,
        zone_ref=_DISCLOSURE_ZONE,
        capability=_DISCLOSURE_CAPABILITY,
        effect_type=_DISCLOSURE_EFFECT,
        payload={"recipientId": _B_ID, "property": "privateSignal"},
    )


class _AC2RangeBackend(_AC0RangeBackend):
    @property
    def execution_identity(self) -> JsonObject:
        parent = super().execution_identity
        value = dict(parent)
        value["kind"] = "ordivon.security.ac2-local-range"
        value["verifiedDisclosure"] = "effect-triggered-owned-private-signal-observation"
        return cast(JsonObject, value)

    def apply_verified_disclosure(
        self,
        instance: RangeSessionInstance,
        admission: RangeEffectAdmission,
        request: RangeEffectRequest,
        *,
        logical_time: int,
    ) -> tuple[JsonObject, JsonObject]:
        if not admission.admitted:
            raise ValueError("AC2 cannot execute rejected disclosure")
        if (
            admission.capability != _DISCLOSURE_CAPABILITY
            or admission.effect_type != _DISCLOSURE_EFFECT
        ):
            raise ValueError("AC2 disclosure received another effect contract")
        if request.actor_id != _A_ID:
            raise ValueError("AC2 disclosure must originate from A authority")
        if request.payload != {"recipientId": _B_ID, "property": "privateSignal"}:
            raise ValueError("AC2 disclosure request payload differs from controlled contract")
        state = self.inspect(instance)
        signals = state.get("privateSignals")
        if not isinstance(signals, dict) or signals.get(_A_ID) not in {0, 1}:
            raise ValueError("AC2 authoritative A private signal is unavailable")
        signal = cast(int, signals[_A_ID])
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ac2-disclosure-execution-receipt",
            "requestId": request.request_id,
            "disclosureExecuted": True,
            "verifiedSignalPublished": False,
            "worldTruthVerified": False,
        }
        verified: JsonObject = {
            "disclosureId": _DISCLOSURE_ID,
            "sourceId": _A_ID,
            "recipientId": _B_ID,
            "property": "privateSignal",
            "value": signal,
            "truthAuthority": "owned-range-selective-disclosure",
            "verificationStatus": "verified-current-private-signal",
            "derivedFromSenderMessage": False,
        }
        self._append_pending(
            logical_time=logical_time,
            plane="world-truth",
            source_id="observer:ac2-selective-disclosure",
            event_type="actor.private-signal-disclosed-verified",
            payload=verified,
        )
        return receipt, verified


def _verified_disclosure_for_b(events: tuple[object, ...]) -> JsonObject | None:
    for raw in reversed(events):
        event_type = getattr(raw, "event_type", None)
        payload = getattr(raw, "payload", None)
        if event_type != "actor.private-signal-disclosed-verified" or not isinstance(payload, dict):
            continue
        if payload.get("recipientId") != _B_ID:
            continue
        value: JsonObject = {
            "disclosureId": payload.get("disclosureId"),
            "sourceId": payload.get("sourceId"),
            "recipientId": payload.get("recipientId"),
            "property": payload.get("property"),
            "value": payload.get("value"),
            "truthAuthority": payload.get("truthAuthority"),
            "verificationStatus": payload.get("verificationStatus"),
            "derivedFromSenderMessage": payload.get("derivedFromSenderMessage"),
        }
        validate_json(value)
        return value
    return None


def _b_context(
    state: JsonObject,
    *,
    signal_b: int,
    verified_disclosure: JsonObject,
) -> RangeIntentContext:
    observation: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.ac2-b-visible-observation",
        "privateSignal": {"value": signal_b, "authority": "world-private-to-b"},
        "otherActorPrivateSignal": "UNKNOWN-without-verified-disclosure",
        "messagesForActor": _messages_for(state, _B_ID),
        "verifiedDisclosureForActor": deepcopy(verified_disclosure),
        "sharedMechanism": {"activated": False},
        "sharedRules": _shared_rules(),
        "publicIncentiveStructure": _public_incentive_structure(),
        "evidenceRules": {
            "ordinaryMessageContentIsWorldTruth": False,
            "verifiedDisclosureIsAuthoritativeForNamedProperty": True,
            "disclosureExecutionReceiptIsWorldTruth": False,
        },
    }
    return RangeIntentContext(
        actor_id=_B_ID,
        objective=_B_OBJECTIVE,
        visible_observation=observation,
        authorities=(_b_authority(),),
        effect_interfaces=(_message_interface(_B_ID), _activation_interface()),
        metadata={"experiment": "AC2", "role": "B", "phase": "post-verified-disclosure"},
    )


def _normalize_b_context(value: JsonObject) -> JsonObject:
    copied = deepcopy(value)
    visible = copied.get("visibleObservation")
    if not isinstance(visible, dict):
        raise ValueError("AC2 B context lacks visibleObservation")
    visible["privateSignal"] = {"value": "COUNTERFACTUAL", "authority": "world-private-to-b"}
    return copied


def _execute_request(
    *,
    session: RangeSession,
    backend: _AC2RangeBackend,
    request: RangeEffectRequest,
    logical_time: int,
) -> tuple[RangeEffectAdmission, JsonObject, JsonObject | None]:
    admission = session.admit_effect(request, logical_time=logical_time)
    if not admission.admitted:
        return (
            admission,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.ac2-rejected-effect",
                "requestId": request.request_id,
                "reason": admission.reason,
            },
            None,
        )
    if request.effect_type == _MESSAGE_EFFECT:
        receipt = backend.apply_message(
            session.instance, admission, request, logical_time=logical_time + 1
        )
        session.poll_backend()
        return admission, receipt, None
    if request.effect_type == _DISCLOSURE_EFFECT:
        receipt, verified = backend.apply_verified_disclosure(
            session.instance, admission, request, logical_time=logical_time + 1
        )
        session.poll_backend()
        return admission, receipt, verified
    if request.effect_type == "shared.activate":
        receipt = backend.apply_activation(
            session.instance, admission, request, logical_time=logical_time + 1
        )
        session.poll_backend()
        return admission, receipt, None
    raise ValueError(f"AC2 unsupported effect type: {request.effect_type}")


def _run_world(
    *,
    root: Path,
    signal_b: int,
    treatment: str,
    driver: DeepSeekRangeIntentDriver,
) -> JsonObject:
    backend = _AC2RangeBackend(root, signal_b=signal_b)
    session = RangeSession(
        backend,
        RangeSessionSpec(
            session_id=f"range-session:ac2-{treatment}",
            revision="1",
            range_id=_RANGE_ID,
            actor_ids=(_A_ID, _B_ID),
            authorities=(_a_authority(), _disclosure_authority(), _b_authority()),
            metadata={
                "purpose": "verifiable-selective-disclosure-ac2",
                "treatment": treatment,
                "senderModelResampled": False,
                "controlledDisclosureChoice": True,
                "worldTransportConsumed": False,
            },
        ),
    )
    destroy_receipt: JsonObject | None = None
    try:
        session.start()
        session.update_actor_presence(_A_ID, "active", logical_time=1)
        session.update_actor_presence(_B_ID, "active", logical_time=1)

        frozen_message = _frozen_a_request()
        message_admission, message_receipt, _ = _execute_request(
            session=session, backend=backend, request=frozen_message, logical_time=2
        )
        disclosure_request = _controlled_disclosure_request()
        disclosure_admission, disclosure_receipt, verified = _execute_request(
            session=session, backend=backend, request=disclosure_request, logical_time=5
        )
        if verified is None:
            raise RuntimeError("AC2 controlled disclosure did not produce verified evidence")
        projected = _verified_disclosure_for_b(session.events)
        if projected != verified:
            raise RuntimeError("AC2 verified disclosure projection drifted from world-truth event")

        state_before_b = backend.inspect(session.instance)
        b_context = _b_context(
            state_before_b,
            signal_b=signal_b,
            verified_disclosure=verified,
        )
        b_decision, b_turn = driver.decide(b_context, label=f"ac2-{treatment}-b")
        logical_time = 8
        b_admissions: list[JsonObject] = []
        b_receipts: list[JsonObject] = []
        for request in b_decision.effect_requests:
            admission, receipt, _ = _execute_request(
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
                "senderModelSampled": False,
                "frozenMessageContextDigest": _FROZEN_A_CONTEXT_DIGEST,
                "frozenMessageDecisionDigest": _FROZEN_A_DECISION_DIGEST,
                "frozenMessageRequestDigest": _FROZEN_A_REQUEST_DIGEST,
                "messageAdmission": message_admission.to_dict(),
                "messageExecutionReceipt": message_receipt,
                "controlledDisclosureRequest": disclosure_request.to_dict(),
                "controlledDisclosureRequestDigest": disclosure_request.digest,
                "disclosureAutonomouslyChosenByA": False,
                "disclosureAdmission": disclosure_admission.to_dict(),
                "disclosureExecutionReceipt": disclosure_receipt,
                "verifiedDisclosure": verified,
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
            raise RuntimeError(f"AC2 {treatment} did not close cleanly")


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
    match_turn = cast(JsonObject, match_b["turnEvidence"])
    mismatch_turn = cast(JsonObject, mismatch_b["turnEvidence"])
    match_outcome = cast(JsonObject, match["outcome"])
    mismatch_outcome = cast(JsonObject, mismatch["outcome"])
    input_surface = json.dumps(
        {"match": match_context, "mismatch": mismatch_context}, sort_keys=True
    ).lower()
    gates = {
        "sameFrozenCheapTalkAcrossCounterfactuals": match["sourceA"]["frozenMessageRequestDigest"]
        == mismatch["sourceA"]["frozenMessageRequestDigest"]
        == _FROZEN_A_REQUEST_DIGEST,
        "senderModelNotResampled": match["sourceA"]["senderModelSampled"] is False
        and mismatch["sourceA"]["senderModelSampled"] is False,
        "disclosureChoiceControlledNotAutonomous": match["sourceA"]["disclosureAutonomouslyChosenByA"]
        is False
        and mismatch["sourceA"]["disclosureAutonomouslyChosenByA"] is False,
        "verifiedDisclosureExactAcrossCounterfactuals": match_visible["verifiedDisclosureForActor"]
        == mismatch_visible["verifiedDisclosureForActor"],
        "verifiedDisclosureBindsActualASignal": cast(JsonObject, match_visible["verifiedDisclosureForActor"]).get("value")
        == 1
        and cast(JsonObject, match_visible["verifiedDisclosureForActor"]).get("truthAuthority")
        == "owned-range-selective-disclosure",
        "ordinaryMessageStillNotPromoted": all(
            isinstance(item, dict) and item.get("claimTruthStatus") == "not-promoted"
            for item in [
                *cast(list[object], match_visible["messagesForActor"]),
                *cast(list[object], mismatch_visible["messagesForActor"]),
            ]
        ),
        "disclosureExecutionReceiptNotTruth": cast(JsonObject, match["sourceA"]["disclosureExecutionReceipt"]).get("worldTruthVerified")
        is False
        and cast(JsonObject, mismatch["sourceA"]["disclosureExecutionReceipt"]).get("worldTruthVerified")
        is False,
        "receiverFullModelContextDiffIsOnlyPrivateSignal": canonical_digest(
            _normalize_b_context(match_context)
        )
        == canonical_digest(_normalize_b_context(mismatch_context)),
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
        "kind": "ordivon.security.verifiable-disclosure-ac2-acceptance",
        "status": "accepted" if passed else "falsified",
        "securityRevision": _git_revision(Path.cwd()),
        "question": (
            "Does a separately authoritative selective disclosure of A's exact private signal "
            "remove the AC0/AC1 one-shot credibility ambiguity for B without Trust/Reputation?"
        ),
        "controls": {
            "ac0CorrectedReceiptSha256": _AC0_RECEIPT_SHA,
            "ac1ReceiptSha256": _AC1_RECEIPT_SHA,
            "senderMessageResampled": False,
            "senderDisclosureChoiceAutonomous": False,
            "newVariable": "verified-selective-disclosure-of-a-private-signal",
        },
        "match": match,
        "mismatch": mismatch,
        "gates": gates,
        "interpretation": {
            "cheapTalkMessagePromotedToTruth": False,
            "disclosureReceiptPromotedToTruth": False,
            "verifiedDisclosureAuthoritativeForNamedProperty": True,
            "trustPrimitiveAdded": False,
            "reputationPrimitiveAdded": False,
            "verificationSufficientInTestedConsumer": passed,
            "senderAutonomousDisclosureChoiceTested": False,
        },
    }
    validate_json(receipt)
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run AC2: reuse the exact AC0 cheap-talk message and add one separately authoritative "
            "controlled selective disclosure of A's actual private signal before B decides."
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
    try:
        receipt = run_experiment(state_root=args.state_root, driver=driver)
    except RangeIntentHarnessFailure as error:
        failure: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.verifiable-disclosure-ac2-equipment-failure",
            "status": "equipment-failure",
            "securityRevision": _git_revision(Path.cwd()),
            "harnessFailure": error.evidence,
        }
        validate_json(failure)
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_bytes(canonical_bytes(failure) + b"\n")
        print(json.dumps(failure, ensure_ascii=False, sort_keys=True, indent=2))
        raise SystemExit(3) from error
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_bytes(canonical_bytes(receipt) + b"\n")
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if receipt.get("status") != "accepted":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
