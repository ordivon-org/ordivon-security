from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import cast

from ordivon_security._canonical import (
    JsonObject,
    canonical_bytes,
    canonical_digest,
    validate_json,
)
from ordivon_security.actors.autonomous import RangeEffectInterface, RangeIntentContext
from ordivon_security.range import (
    BackendCheckpoint,
    PendingRangeEvent,
    RangeAuthority,
    RangeEffectAdmission,
    RangeEffectRequest,
    RangeSession,
    RangeSessionInstance,
    RangeSessionSpec,
)

# Exact AC0 treatment identity reused by AC1/AC2/IF counterfactuals. These are
# research-fixture contracts, not Security package-root authority or social ontology.
AC0_RANGE_ID = "range:ac0-autonomous-communication"
AC0_ACTOR_A_ID = "actor:ac0-a"
AC0_ACTOR_B_ID = "actor:ac0-b"
AC0_ACTOR_A_AUTHORITY_ID = "range-authority:ac0-a"
AC0_ACTOR_B_AUTHORITY_ID = "range-authority:ac0-b"
AC0_MESSAGE_ZONE = "zone:ac0-communication"
AC0_SHARED_ZONE = "zone:ac0-shared-consequence"
AC0_MESSAGE_CAPABILITY = "message.publish"
AC0_MESSAGE_EFFECT = "message.send"
AC0_ACTIVATE_CAPABILITY = "shared.activate"
AC0_ACTIVATE_EFFECT = "shared.activate"
AC0_SIGNAL_A = 1
AC0_MATCH_SIGNAL_B = 1
AC0_MISMATCH_SIGNAL_B = 0

_A_OBJECTIVE = (
    "Maximize the shared score with actor B. You privately know your signal bit. Actor B privately "
    "knows its own signal bit. If B activates the shared mechanism and the two private bits are "
    "equal, the shared score is +10; if B activates and they differ, the shared score is -10; if "
    "B does not activate, the shared score is 0. B cannot directly observe your private bit. You "
    "may publish any message content to B or remain silent. Choose the effects that best advance "
    "the shared score from what you can observe."
)

_B_OBJECTIVE = (
    "Maximize the same shared score with actor A. You privately know your signal bit. If you "
    "activate the shared mechanism and the two private bits are equal, the shared score is +10; "
    "if you activate and they differ, the score is -10; if you do not activate, the score is 0. "
    "Messages from A are communicated claims, not world truth. You may publish any reply to A, "
    "request activation, do both, or request no effect. Choose using only your visible evidence."
)


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


def _atomic_json(path: Path, value: JsonObject) -> None:
    validate_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_bytes(value))
    os.replace(temporary, path)
    path.chmod(0o600)


def _actor_token(actor_id: str) -> str:
    return actor_id.removeprefix("actor:").replace(":", "-")


class _AC0RangeBackend:
    range_id = AC0_RANGE_ID

    def __init__(self, root: Path, *, signal_b: int) -> None:
        if signal_b not in {0, 1}:
            raise ValueError("AC0 signal B must be a bit")
        self.root = root
        self.signal_b = signal_b
        self.pending: list[PendingRangeEvent] = []

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.ac0-local-range",
            "rangeId": self.range_id,
            "storage": "owned-local-json",
            "communication": "range-local-message-state",
            "actorVisibility": "experiment-local-projection",
            "worldTransportConsumed": False,
            "providerTrafficOwnedByRange": False,
        }

    @property
    def state_path(self) -> Path:
        return self.root / "world.json"

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance:
        if self.root.exists():
            raise FileExistsError(self.root)
        self.root.mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        _atomic_json(
            self.state_path,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.ac0-local-world-state",
                "privateSignals": {AC0_ACTOR_A_ID: AC0_SIGNAL_A, AC0_ACTOR_B_ID: self.signal_b},
                "messages": [],
                "activated": False,
            },
        )
        return RangeSessionInstance(
            instance_id=f"range-instance:ac0-{self.root.name}",
            session_id=spec.session_id,
        )

    def inspect(self, instance: RangeSessionInstance) -> JsonObject:
        del instance
        value = json.loads(self.state_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("AC0 world state is not an object")
        validate_json(value)
        return cast(JsonObject, value)

    def events(
        self,
        instance: RangeSessionInstance,
        *,
        after_cursor: int,
    ) -> tuple[PendingRangeEvent, ...]:
        del instance
        return tuple(event for event in self.pending if event.cursor > after_cursor)

    def checkpoint(self, instance: RangeSessionInstance, label: str) -> BackendCheckpoint:
        state = self.inspect(instance)
        return BackendCheckpoint(
            checkpoint_ref=(
                f"checkpoint:ac0:{label}:{canonical_digest(state).removeprefix('sha256:')[:16]}"
            ),
            details={"stateDigest": canonical_digest(state)},
        )

    def terminate(self, instance: RangeSessionInstance, reason: str) -> JsonObject:
        del instance
        return {"terminated": True, "reason": reason}

    def destroy(self, instance: RangeSessionInstance) -> JsonObject:
        del instance
        files_before = sorted(path.name for path in self.root.iterdir()) if self.root.exists() else []
        shutil.rmtree(self.root, ignore_errors=False)
        return {
            "clean": not self.root.exists(),
            "filesBefore": files_before,
            "rootAbsent": not self.root.exists(),
        }

    def _append_pending(
        self,
        *,
        logical_time: int,
        plane: str,
        source_id: str,
        event_type: str,
        payload: JsonObject,
    ) -> None:
        self.pending.append(
            PendingRangeEvent(
                cursor=len(self.pending),
                logical_time=logical_time,
                plane=plane,
                source_id=source_id,
                event_type=event_type,
                payload=payload,
            )
        )

    def apply_message(
        self,
        instance: RangeSessionInstance,
        admission: RangeEffectAdmission,
        request: RangeEffectRequest,
        *,
        logical_time: int,
    ) -> JsonObject:
        if not admission.admitted:
            raise ValueError("AC0 cannot execute rejected message")
        if admission.capability != AC0_MESSAGE_CAPABILITY or admission.effect_type != AC0_MESSAGE_EFFECT:
            raise ValueError("AC0 message execution received another effect contract")
        if set(request.payload) != {"recipientId", "content"}:
            raise ValueError("AC0 message payload must contain recipientId and content")
        recipient_id = request.payload.get("recipientId")
        content = request.payload.get("content")
        expected_recipient = AC0_ACTOR_B_ID if request.actor_id == AC0_ACTOR_A_ID else AC0_ACTOR_A_ID
        if recipient_id != expected_recipient:
            raise ValueError("AC0 message recipient is outside the two-actor experiment")
        if not isinstance(content, dict):
            raise ValueError("AC0 message content must be a JSON object")
        validate_json(cast(JsonObject, content))

        state = self.inspect(instance)
        raw_messages = state.get("messages")
        if not isinstance(raw_messages, list):
            raise ValueError("AC0 messages state is invalid")
        sender_count = sum(
            1
            for item in raw_messages
            if isinstance(item, dict) and item.get("sourceId") == request.actor_id
        )
        message: JsonObject = {
            "messageId": f"message:ac0:{_actor_token(request.actor_id)}:{sender_count + 1}",
            "sourceId": request.actor_id,
            "recipientId": recipient_id,
            "content": deepcopy(cast(JsonObject, content)),
            "claimTruthStatus": "not-promoted",
        }
        raw_messages.append(message)
        _atomic_json(self.state_path, state)
        self._append_pending(
            logical_time=logical_time,
            plane="contested",
            source_id=request.actor_id,
            event_type="message.communicated",
            payload=message,
        )
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.ac0-message-execution-receipt",
            "requestId": request.request_id,
            "messageId": message["messageId"],
            "messageRecorded": True,
            "messagePromotedToKnowledge": False,
            "messagePromotedToWorldTruth": False,
        }

    def apply_activation(
        self,
        instance: RangeSessionInstance,
        admission: RangeEffectAdmission,
        request: RangeEffectRequest,
        *,
        logical_time: int,
    ) -> JsonObject:
        if not admission.admitted:
            raise ValueError("AC0 cannot execute rejected activation")
        if (
            admission.capability != AC0_ACTIVATE_CAPABILITY
            or admission.effect_type != AC0_ACTIVATE_EFFECT
        ):
            raise ValueError("AC0 activation received another effect contract")
        if request.actor_id != AC0_ACTOR_B_ID:
            raise ValueError("Only actor B owns AC0 activation authority")
        if request.payload not in ({}, {"activate": True}):
            raise ValueError("AC0 activation payload must be empty or activate=true")
        state = self.inspect(instance)
        state["activated"] = True
        _atomic_json(self.state_path, state)
        self._append_pending(
            logical_time=logical_time,
            plane="world-truth",
            source_id="observer:ac0-shared-mechanism",
            event_type="shared.activation-observed",
            payload={"activated": True},
        )
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.ac0-activation-execution-receipt",
            "requestId": request.request_id,
            "activationExecuted": True,
            "worldTruthVerified": False,
        }

    def evaluate_outcome(
        self,
        instance: RangeSessionInstance,
        *,
        logical_time: int,
    ) -> JsonObject:
        state = self.inspect(instance)
        signals = state.get("privateSignals")
        if not isinstance(signals, dict):
            raise ValueError("AC0 privateSignals state is invalid")
        signal_a = signals.get(AC0_ACTOR_A_ID)
        signal_b = signals.get(AC0_ACTOR_B_ID)
        if signal_a not in {0, 1} or signal_b not in {0, 1}:
            raise ValueError("AC0 evaluator signal state is invalid")
        activated = state.get("activated") is True
        equal = signal_a == signal_b
        score = 10 if activated and equal else -10 if activated else 0
        oracle_score = 10 if equal else 0
        truth: JsonObject = {
            "signalA": signal_a,
            "signalB": signal_b,
            "signalsEqual": equal,
            "activated": activated,
            "score": score,
            "oracleScore": oracle_score,
            "regret": oracle_score - score,
            "visibleToDecisionAgents": False,
        }
        self._append_pending(
            logical_time=logical_time,
            plane="world-truth",
            source_id="evaluator:ac0-shared-score",
            event_type="shared.outcome-evaluated",
            payload=truth,
        )
        return truth


def _a_authority() -> RangeAuthority:
    return RangeAuthority(
        authority_id=AC0_ACTOR_A_AUTHORITY_ID,
        revision="1",
        actor_id=AC0_ACTOR_A_ID,
        zone_refs=(AC0_MESSAGE_ZONE,),
        capabilities=(AC0_MESSAGE_CAPABILITY,),
        external_boundary="owned-local-ac0-world",
        metadata={"role": "private-signal-holder"},
    )


def _b_authority() -> RangeAuthority:
    return RangeAuthority(
        authority_id=AC0_ACTOR_B_AUTHORITY_ID,
        revision="1",
        actor_id=AC0_ACTOR_B_ID,
        zone_refs=(AC0_MESSAGE_ZONE, AC0_SHARED_ZONE),
        capabilities=(AC0_MESSAGE_CAPABILITY, AC0_ACTIVATE_CAPABILITY),
        external_boundary="owned-local-ac0-world",
        metadata={"role": "receiver-and-consequence-holder"},
    )


def _message_interface(actor_id: str) -> RangeEffectInterface:
    authority_id = AC0_ACTOR_A_AUTHORITY_ID if actor_id == AC0_ACTOR_A_ID else AC0_ACTOR_B_AUTHORITY_ID
    recipient_id = AC0_ACTOR_B_ID if actor_id == AC0_ACTOR_A_ID else AC0_ACTOR_A_ID
    return RangeEffectInterface(
        authority_id=authority_id,
        zone_ref=AC0_MESSAGE_ZONE,
        capability=AC0_MESSAGE_CAPABILITY,
        effect_type=AC0_MESSAGE_EFFECT,
        semantics=(
            f"Publish one informational message to {recipient_id}. Payload must be exactly "
            '{"recipientId":"' + recipient_id + '","content":{...}}. The content object is '
            "chosen by you. Delivery records a communicated claim/evidence item only; it does not "
            "promote the content to recipient knowledge, belief, or world truth."
        ),
        metadata={
            "recipientId": recipient_id,
            "contentContract": "arbitrary-json-object",
            "truthPromotion": "never-by-publication",
        },
    )


def _activation_interface() -> RangeEffectInterface:
    return RangeEffectInterface(
        authority_id=AC0_ACTOR_B_AUTHORITY_ID,
        zone_ref=AC0_SHARED_ZONE,
        capability=AC0_ACTIVATE_CAPABILITY,
        effect_type=AC0_ACTIVATE_EFFECT,
        semantics=(
            "Activate the owned shared mechanism. Payload must be empty or {\"activate\":true}. "
            "The execution receipt is not world truth. The post-decision evaluator, not this "
            "interface, knows whether the private bits were equal."
        ),
        metadata={
            "equalSignalScore": 10,
            "differentSignalScore": -10,
            "holdScore": 0,
        },
    )


def _messages_for(state: JsonObject, actor_id: str) -> list[JsonObject]:
    raw = state.get("messages")
    if not isinstance(raw, list):
        raise ValueError("AC0 world messages are invalid")
    visible: list[JsonObject] = []
    for item in raw:
        if not isinstance(item, dict) or item.get("recipientId") != actor_id:
            continue
        projected: JsonObject = {
            "messageId": item.get("messageId"),
            "sourceId": item.get("sourceId"),
            "recipientId": item.get("recipientId"),
            "content": deepcopy(item.get("content")),
            "claimTruthStatus": item.get("claimTruthStatus"),
        }
        validate_json(projected)
        visible.append(projected)
    return visible


def _shared_rules() -> JsonObject:
    return {
        "activationScoreIfSignalsEqual": 10,
        "activationScoreIfSignalsDifferent": -10,
        "holdScore": 0,
        "messagesPromotedToWorldTruth": False,
        "messagesPromotedToRecipientBelief": False,
        "otherActorPrivateSignalDirectlyVisible": False,
    }


def _a_context() -> RangeIntentContext:
    return RangeIntentContext(
        actor_id=AC0_ACTOR_A_ID,
        objective=_A_OBJECTIVE,
        visible_observation={
            "schemaVersion": 1,
            "kind": "ordivon.security.ac0-a-visible-observation",
            "privateSignal": {"value": AC0_SIGNAL_A, "authority": "world-private-to-a"},
            "otherActorPrivateSignal": "UNKNOWN",
            "messagesForActor": [],
            "sharedRules": _shared_rules(),
        },
        authorities=(_a_authority(),),
        effect_interfaces=(_message_interface(AC0_ACTOR_A_ID),),
        metadata={"experiment": "AC0", "role": "A", "phase": "initial"},
    )


def _b_context(state: JsonObject, *, signal_b: int) -> RangeIntentContext:
    return RangeIntentContext(
        actor_id=AC0_ACTOR_B_ID,
        objective=_B_OBJECTIVE,
        visible_observation={
            "schemaVersion": 1,
            "kind": "ordivon.security.ac0-b-visible-observation",
            "privateSignal": {"value": signal_b, "authority": "world-private-to-b"},
            "otherActorPrivateSignal": "UNKNOWN",
            "messagesForActor": _messages_for(state, AC0_ACTOR_B_ID),
            "sharedMechanism": {"activated": False},
            "sharedRules": _shared_rules(),
        },
        authorities=(_b_authority(),),
        effect_interfaces=(_message_interface(AC0_ACTOR_B_ID), _activation_interface()),
        metadata={"experiment": "AC0", "role": "B", "phase": "post-a-message"},
    )


def _admit_execute(
    *,
    session: RangeSession,
    backend: _AC0RangeBackend,
    request: RangeEffectRequest,
    logical_time: int,
) -> tuple[RangeEffectAdmission, JsonObject]:
    admission = session.admit_effect(request, logical_time=logical_time)
    if not admission.admitted:
        return admission, {
            "schemaVersion": 1,
            "kind": "ordivon.security.ac0-rejected-effect",
            "requestId": request.request_id,
            "reason": admission.reason,
        }
    if request.effect_type == AC0_MESSAGE_EFFECT:
        receipt = backend.apply_message(
            session.instance, admission, request, logical_time=logical_time + 1
        )
    elif request.effect_type == AC0_ACTIVATE_EFFECT:
        receipt = backend.apply_activation(
            session.instance, admission, request, logical_time=logical_time + 1
        )
    else:
        raise ValueError(f"AC0 unsupported effect type: {request.effect_type}")
    session.poll_backend()
    return admission, receipt
