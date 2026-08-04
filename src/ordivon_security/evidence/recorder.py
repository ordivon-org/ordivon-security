from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json

from .events import EvidenceChannel, EvidenceEvent
from .operational import OperationalEvidenceEvent


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    path: Path
    manifest: JsonObject
    digest: str
    operational_manifest: JsonObject
    operational_digest: str


class EvidenceRecorder:
    def __init__(self, trial_id: str) -> None:
        self.trial_id = trial_id
        self._events: dict[EvidenceChannel, list[EvidenceEvent]] = {
            channel: [] for channel in EvidenceChannel
        }
        self._operational_events: list[OperationalEvidenceEvent] = []

    def append(
        self,
        channel: EvidenceChannel,
        *,
        logical_time: int,
        source_id: str,
        event_type: str,
        payload: JsonObject,
    ) -> EvidenceEvent:
        events = self._events[channel]
        event = EvidenceEvent.create(
            trial_id=self.trial_id,
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
            trial_id=self.trial_id,
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
        scenario_manifest: JsonObject,
        trial_identity: JsonObject,
        raw_metrics: JsonObject,
        result: JsonObject,
    ) -> EvidenceBundle:
        if output_path.exists() and any(output_path.iterdir()):
            raise FileExistsError(f"Evidence output path is not empty: {output_path}")
        events_path = output_path / "events"
        events_path.mkdir(parents=True, exist_ok=True)
        channel_manifest: JsonObject = {}
        for channel in EvidenceChannel:
            file_path = events_path / f"{channel.value}.jsonl"
            lines = b"".join(
                canonical_bytes(event.to_dict()) + b"\n" for event in self._events[channel]
            )
            file_path.write_bytes(lines)
            channel_manifest[channel.value] = {
                "path": f"events/{channel.value}.jsonl",
                "eventCount": len(self._events[channel]),
                "headDigest": None
                if not self._events[channel]
                else self._events[channel][-1].event_digest,
                "fileDigest": "sha256:" + hashlib.sha256(lines).hexdigest(),
            }
        (output_path / "manifest.json").write_bytes(canonical_bytes(scenario_manifest) + b"\n")
        (output_path / "trial-identity.json").write_bytes(canonical_bytes(trial_identity) + b"\n")
        (output_path / "raw-metrics.json").write_bytes(canonical_bytes(raw_metrics) + b"\n")
        (output_path / "result.json").write_bytes(canonical_bytes(result) + b"\n")
        bundle_manifest: JsonObject = {
            "schemaVersion": 2,
            "kind": "ordivon.security.evidence-bundle",
            "trialId": self.trial_id,
            "scenarioManifestDigest": canonical_digest(scenario_manifest),
            "trialIdentityDigest": canonical_digest(trial_identity),
            "rawMetricsDigest": canonical_digest(raw_metrics),
            "resultDigest": canonical_digest(result),
            "channels": channel_manifest,
        }
        (output_path / "bundle-manifest.json").write_bytes(canonical_bytes(bundle_manifest) + b"\n")
        semantic_digest = canonical_digest(bundle_manifest)

        operational_path = events_path / "operational.jsonl"
        operational_lines = b"".join(
            canonical_bytes(event.to_dict()) + b"\n" for event in self._operational_events
        )
        operational_path.write_bytes(operational_lines)
        operational_manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.operational-evidence",
            "trialId": self.trial_id,
            "semanticEvidenceDigest": semantic_digest,
            "path": "events/operational.jsonl",
            "eventCount": len(self._operational_events),
            "headDigest": None
            if not self._operational_events
            else self._operational_events[-1].event_digest,
            "fileDigest": "sha256:" + hashlib.sha256(operational_lines).hexdigest(),
        }
        (output_path / "operational-manifest.json").write_bytes(
            canonical_bytes(operational_manifest) + b"\n"
        )
        return EvidenceBundle(
            output_path,
            bundle_manifest,
            semantic_digest,
            operational_manifest,
            canonical_digest(operational_manifest),
        )


def _load_object(path: Path, label: str) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    validate_json(value)
    return value


def verify_evidence_bundle(path: Path) -> str:
    manifest = _load_object(path / "bundle-manifest.json", "Evidence bundle manifest")
    if manifest.get("schemaVersion") != 2:
        raise ValueError("Evidence bundle schema revision is unsupported")
    channels = manifest.get("channels")
    if not isinstance(channels, dict):
        raise ValueError("Evidence bundle channels are missing")
    trial_id = manifest.get("trialId")
    if not isinstance(trial_id, str):
        raise ValueError("Evidence bundle Trial identity is missing")
    for channel in EvidenceChannel:
        metadata = channels.get(channel.value)
        if not isinstance(metadata, dict):
            raise ValueError(f"Evidence channel metadata is missing: {channel.value}")
        relative_path = metadata.get("path")
        if not isinstance(relative_path, str):
            raise ValueError("Evidence channel path is invalid")
        raw = (path / relative_path).read_bytes()
        actual_file_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if actual_file_digest != metadata.get("fileDigest"):
            raise ValueError(f"Evidence channel file digest differs: {channel.value}")
        previous: str | None = None
        count = 0
        for line in raw.splitlines():
            value: Any = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("Evidence event must be an object")
            if value.get("trialId") != trial_id or value.get("channel") != channel.value:
                raise ValueError("Evidence event identity differs from bundle")
            if value.get("sequence") != count or value.get("previousDigest") != previous:
                raise ValueError("Evidence event chain is discontinuous")
            payload = value.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("Evidence event payload must be an object")
            if canonical_digest(payload) != value.get("payloadDigest"):
                raise ValueError("Evidence event payload digest differs")
            unsigned = dict(value)
            event_digest = unsigned.pop("eventDigest", None)
            if canonical_digest(unsigned) != event_digest:
                raise ValueError("Evidence event digest differs")
            previous = event_digest
            count += 1
        if count != metadata.get("eventCount") or previous != metadata.get("headDigest"):
            raise ValueError("Evidence channel summary differs")
    scenario = _load_object(path / "manifest.json", "Scenario manifest")
    identity = _load_object(path / "trial-identity.json", "Trial identity")
    metrics = _load_object(path / "raw-metrics.json", "Raw metrics")
    result = _load_object(path / "result.json", "Contest result")
    if canonical_digest(scenario) != manifest.get("scenarioManifestDigest"):
        raise ValueError("Scenario manifest digest differs")
    if canonical_digest(identity) != manifest.get("trialIdentityDigest"):
        raise ValueError("Trial identity digest differs")
    if canonical_digest(metrics) != manifest.get("rawMetricsDigest"):
        raise ValueError("Raw metrics digest differs")
    if canonical_digest(result) != manifest.get("resultDigest"):
        raise ValueError("Contest result digest differs")
    return canonical_digest(manifest)


def verify_operational_evidence(path: Path) -> str:
    semantic_digest = verify_evidence_bundle(path)
    manifest = _load_object(path / "operational-manifest.json", "Operational evidence manifest")
    if manifest.get("semanticEvidenceDigest") != semantic_digest:
        raise ValueError("Operational evidence is bound to another semantic bundle")
    trial_id = manifest.get("trialId")
    relative_path = manifest.get("path")
    if not isinstance(trial_id, str) or not isinstance(relative_path, str):
        raise ValueError("Operational evidence identity or path is invalid")
    raw = (path / relative_path).read_bytes()
    actual_file_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual_file_digest != manifest.get("fileDigest"):
        raise ValueError("Operational evidence file digest differs")
    previous: str | None = None
    count = 0
    for line in raw.splitlines():
        value: Any = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("Operational evidence event must be an object")
        if value.get("trialId") != trial_id:
            raise ValueError("Operational evidence Trial identity differs")
        if value.get("sequence") != count or value.get("previousDigest") != previous:
            raise ValueError("Operational evidence chain is discontinuous")
        payload = value.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("Operational evidence payload must be an object")
        if canonical_digest(payload) != value.get("payloadDigest"):
            raise ValueError("Operational evidence payload differs")
        unsigned = dict(value)
        event_digest = unsigned.pop("eventDigest", None)
        if canonical_digest(unsigned) != event_digest:
            raise ValueError("Operational evidence event digest differs")
        previous = event_digest
        count += 1
    if count != manifest.get("eventCount") or previous != manifest.get("headDigest"):
        raise ValueError("Operational evidence summary differs")
    return canonical_digest(manifest)
