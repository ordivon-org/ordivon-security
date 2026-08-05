from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.evidence.operational import OperationalEvidenceEvent


class EvaluationEvidenceChannel(StrEnum):
    SAMPLE = "sample"
    MANAGEMENT = "management"
    OBSERVER = "observer"
    GUARDIAN = "guardian"
    TRUTH = "world-truth"


@dataclass(frozen=True, slots=True)
class EvaluationEvidenceEvent:
    event_id: str
    run_id: str
    channel: EvaluationEvidenceChannel
    sequence: int
    logical_time: int
    source_id: str
    event_type: str
    payload: JsonObject
    previous_digest: str | None
    payload_digest: str
    event_digest: str

    def to_dict(self) -> JsonObject:
        return {
            "eventId": self.event_id,
            "runId": self.run_id,
            "channel": self.channel.value,
            "sequence": self.sequence,
            "logicalTime": self.logical_time,
            "sourceId": self.source_id,
            "eventType": self.event_type,
            "payload": self.payload,
            "previousDigest": self.previous_digest,
            "payloadDigest": self.payload_digest,
            "eventDigest": self.event_digest,
        }

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        channel: EvaluationEvidenceChannel,
        sequence: int,
        logical_time: int,
        source_id: str,
        event_type: str,
        payload: JsonObject,
        previous_digest: str | None,
    ) -> EvaluationEvidenceEvent:
        validate_json(payload)
        event_id = f"evaluation-event:{channel.value}:{sequence}"
        payload_digest = canonical_digest(payload)
        unsigned: JsonObject = {
            "eventId": event_id,
            "runId": run_id,
            "channel": channel.value,
            "sequence": sequence,
            "logicalTime": logical_time,
            "sourceId": source_id,
            "eventType": event_type,
            "payload": payload,
            "previousDigest": previous_digest,
            "payloadDigest": payload_digest,
        }
        return cls(
            event_id=event_id,
            run_id=run_id,
            channel=channel,
            sequence=sequence,
            logical_time=logical_time,
            source_id=source_id,
            event_type=event_type,
            payload=payload,
            previous_digest=previous_digest,
            payload_digest=payload_digest,
            event_digest=canonical_digest(unsigned),
        )


@dataclass(frozen=True, slots=True)
class EvaluationEvidenceBundle:
    path: Path
    digest: str
    operational_digest: str


class EvaluationEvidenceRecorder:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self._events: dict[EvaluationEvidenceChannel, list[EvaluationEvidenceEvent]] = {
            channel: [] for channel in EvaluationEvidenceChannel
        }
        self._operational_events: list[OperationalEvidenceEvent] = []

    def append(
        self,
        channel: EvaluationEvidenceChannel,
        *,
        logical_time: int,
        source_id: str,
        event_type: str,
        payload: JsonObject,
    ) -> EvaluationEvidenceEvent:
        events = self._events[channel]
        event = EvaluationEvidenceEvent.create(
            run_id=self.run_id,
            channel=channel,
            sequence=len(events),
            logical_time=logical_time,
            source_id=source_id,
            event_type=event_type,
            payload=payload,
            previous_digest=None if not events else events[-1].event_digest,
        )
        events.append(event)
        return event

    def append_operational(
        self,
        *,
        recorded_at_ms: int,
        source_id: str,
        event_type: str,
        payload: JsonObject,
    ) -> OperationalEvidenceEvent:
        event = OperationalEvidenceEvent.create(
            trial_id=self.run_id,
            sequence=len(self._operational_events),
            recorded_at_ms=recorded_at_ms,
            source_id=source_id,
            event_type=event_type,
            payload=payload,
            previous_digest=(
                None if not self._operational_events else self._operational_events[-1].event_digest
            ),
        )
        self._operational_events.append(event)
        return event

    def seal(
        self,
        output_path: Path,
        *,
        evaluation_spec: JsonObject,
        execution_identity: JsonObject,
        findings: JsonObject,
        result: JsonObject,
    ) -> EvaluationEvidenceBundle:
        if output_path.exists() and any(output_path.iterdir()):
            raise FileExistsError(f"Evaluation evidence path is not empty: {output_path}")
        events_path = output_path / "events"
        events_path.mkdir(parents=True, exist_ok=True)
        channel_manifest: JsonObject = {}
        for channel in EvaluationEvidenceChannel:
            file_path = events_path / f"{channel.value}.jsonl"
            raw = b"".join(
                canonical_bytes(event.to_dict()) + b"\n" for event in self._events[channel]
            )
            file_path.write_bytes(raw)
            channel_manifest[channel.value] = {
                "path": f"events/{channel.value}.jsonl",
                "eventCount": len(self._events[channel]),
                "headDigest": None
                if not self._events[channel]
                else self._events[channel][-1].event_digest,
                "fileDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }
        named_objects = {
            "evaluation-spec.json": evaluation_spec,
            "execution-identity.json": execution_identity,
            "findings.json": findings,
            "result.json": result,
        }
        for name, value in named_objects.items():
            (output_path / name).write_bytes(canonical_bytes(value) + b"\n")
        manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.evaluation-evidence-bundle",
            "runId": self.run_id,
            "evaluationSpecDigest": canonical_digest(evaluation_spec),
            "executionIdentityDigest": canonical_digest(execution_identity),
            "findingsDigest": canonical_digest(findings),
            "resultDigest": canonical_digest(result),
            "channels": channel_manifest,
        }
        (output_path / "bundle-manifest.json").write_bytes(canonical_bytes(manifest) + b"\n")
        semantic_digest = canonical_digest(manifest)

        operational_path = events_path / "operational.jsonl"
        operational_raw = b"".join(
            canonical_bytes(event.to_dict()) + b"\n" for event in self._operational_events
        )
        operational_path.write_bytes(operational_raw)
        operational_manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.evaluation-operational-evidence",
            "runId": self.run_id,
            "semanticEvidenceDigest": semantic_digest,
            "path": "events/operational.jsonl",
            "eventCount": len(self._operational_events),
            "headDigest": None
            if not self._operational_events
            else self._operational_events[-1].event_digest,
            "fileDigest": "sha256:" + hashlib.sha256(operational_raw).hexdigest(),
        }
        (output_path / "operational-manifest.json").write_bytes(
            canonical_bytes(operational_manifest) + b"\n"
        )
        return EvaluationEvidenceBundle(
            path=output_path,
            digest=semantic_digest,
            operational_digest=canonical_digest(operational_manifest),
        )


def _load_object(path: Path, label: str) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    validate_json(value)
    return value


def verify_evaluation_evidence(path: Path) -> str:
    manifest = _load_object(path / "bundle-manifest.json", "Evaluation bundle manifest")
    if manifest.get("schemaVersion") != 1:
        raise ValueError("Evaluation evidence schema revision is unsupported")
    run_id = manifest.get("runId")
    channels = manifest.get("channels")
    if not isinstance(run_id, str) or not isinstance(channels, dict):
        raise ValueError("Evaluation evidence identity or channels are missing")
    for channel in EvaluationEvidenceChannel:
        metadata = channels.get(channel.value)
        if not isinstance(metadata, dict):
            raise ValueError(f"Evaluation channel metadata is missing: {channel.value}")
        relative_path = metadata.get("path")
        if not isinstance(relative_path, str):
            raise ValueError("Evaluation channel path is invalid")
        raw = (path / relative_path).read_bytes()
        if "sha256:" + hashlib.sha256(raw).hexdigest() != metadata.get("fileDigest"):
            raise ValueError(f"Evaluation channel file digest differs: {channel.value}")
        previous: str | None = None
        count = 0
        for line in raw.splitlines():
            value: Any = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("Evaluation event must be an object")
            if value.get("runId") != run_id or value.get("channel") != channel.value:
                raise ValueError("Evaluation event identity differs from bundle")
            if value.get("sequence") != count or value.get("previousDigest") != previous:
                raise ValueError("Evaluation event chain is discontinuous")
            payload = value.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("Evaluation event payload must be an object")
            if canonical_digest(payload) != value.get("payloadDigest"):
                raise ValueError("Evaluation event payload digest differs")
            unsigned = dict(value)
            event_digest = unsigned.pop("eventDigest", None)
            if canonical_digest(unsigned) != event_digest:
                raise ValueError("Evaluation event digest differs")
            previous = event_digest
            count += 1
        if count != metadata.get("eventCount") or previous != metadata.get("headDigest"):
            raise ValueError("Evaluation channel summary differs")
    named = (
        ("evaluation-spec.json", "evaluationSpecDigest"),
        ("execution-identity.json", "executionIdentityDigest"),
        ("findings.json", "findingsDigest"),
        ("result.json", "resultDigest"),
    )
    for filename, digest_field in named:
        value = _load_object(path / filename, filename)
        if canonical_digest(value) != manifest.get(digest_field):
            raise ValueError(f"Evaluation object digest differs: {filename}")
    return canonical_digest(manifest)


def verify_evaluation_operational_evidence(path: Path) -> str:
    semantic_digest = verify_evaluation_evidence(path)
    manifest = _load_object(
        path / "operational-manifest.json",
        "Evaluation operational evidence manifest",
    )
    if manifest.get("semanticEvidenceDigest") != semantic_digest:
        raise ValueError("Evaluation operational evidence binds another semantic bundle")
    run_id = manifest.get("runId")
    relative_path = manifest.get("path")
    if not isinstance(run_id, str) or not isinstance(relative_path, str):
        raise ValueError("Evaluation operational identity or path is invalid")
    raw = (path / relative_path).read_bytes()
    if "sha256:" + hashlib.sha256(raw).hexdigest() != manifest.get("fileDigest"):
        raise ValueError("Evaluation operational file digest differs")
    previous: str | None = None
    count = 0
    for line in raw.splitlines():
        value: Any = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("Evaluation operational event must be an object")
        if value.get("trialId") != run_id:
            raise ValueError("Evaluation operational Run identity differs")
        if value.get("sequence") != count or value.get("previousDigest") != previous:
            raise ValueError("Evaluation operational chain is discontinuous")
        payload = value.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("Evaluation operational payload must be an object")
        if canonical_digest(payload) != value.get("payloadDigest"):
            raise ValueError("Evaluation operational payload digest differs")
        unsigned = dict(value)
        event_digest = unsigned.pop("eventDigest", None)
        if canonical_digest(unsigned) != event_digest:
            raise ValueError("Evaluation operational event digest differs")
        previous = event_digest
        count += 1
    if count != manifest.get("eventCount") or previous != manifest.get("headDigest"):
        raise ValueError("Evaluation operational summary differs")
    return canonical_digest(manifest)
