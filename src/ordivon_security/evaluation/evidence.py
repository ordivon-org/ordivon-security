from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from ordivon_security._canonical import (
    JsonObject,
    JsonValue,
    canonical_bytes,
    canonical_digest,
    validate_json,
)
from ordivon_security._paths import resolve_relative_regular_file
from ordivon_security.evidence.operational import OperationalEvidenceEvent

from .backend import EvaluationArtifact


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


def _write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def _digest_path(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_length = 0
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
            byte_length += len(chunk)
    return "sha256:" + digest.hexdigest(), byte_length


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
        artifacts: tuple[EvaluationArtifact, ...] = (),
    ) -> EvaluationEvidenceBundle:
        if output_path.is_symlink():
            raise ValueError("Evaluation evidence output path must not be a symbolic link")
        if output_path.exists() and (not output_path.is_dir() or any(output_path.iterdir())):
            raise FileExistsError(
                f"Evaluation evidence path is not an empty directory: {output_path}"
            )
        output_path.mkdir(parents=True, exist_ok=True)
        output_path.chmod(0o700)
        events_path = output_path / "events"
        events_path.mkdir(exist_ok=True)
        events_path.chmod(0o700)

        channel_manifest: JsonObject = {}
        for channel in EvaluationEvidenceChannel:
            file_path = events_path / f"{channel.value}.jsonl"
            raw = b"".join(
                canonical_bytes(event.to_dict()) + b"\n" for event in self._events[channel]
            )
            _write_private(file_path, raw)
            channel_manifest[channel.value] = {
                "path": f"events/{channel.value}.jsonl",
                "eventCount": len(self._events[channel]),
                "headDigest": None
                if not self._events[channel]
                else self._events[channel][-1].event_digest,
                "fileDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }

        artifact_manifest: list[JsonValue] = []
        if artifacts:
            artifacts_path = output_path / "artifacts"
            artifacts_path.mkdir()
            artifacts_path.chmod(0o700)
            for index, artifact in enumerate(artifacts):
                source = artifact.source_path
                if source is None or not source.is_file() or source.is_symlink():
                    raise ValueError("Evaluation Artifact source is missing or unsafe")
                digest, byte_length = _digest_path(source)
                if digest != artifact.digest or byte_length != artifact.byte_length:
                    raise ValueError("Evaluation Artifact source differs from declared identity")
                destination = artifacts_path / (
                    f"{index:03d}-{artifact.digest.removeprefix('sha256:')[:16]}.bin"
                )
                with source.open("rb") as source_handle, destination.open("xb") as target_handle:
                    shutil.copyfileobj(source_handle, target_handle, length=4 * 1024 * 1024)
                    target_handle.flush()
                destination.chmod(0o600)
                entry = artifact.to_dict()
                entry["path"] = str(destination.relative_to(output_path))
                artifact_manifest.append(entry)

        named_objects = {
            "evaluation-spec.json": evaluation_spec,
            "execution-identity.json": execution_identity,
            "findings.json": findings,
            "result.json": result,
        }
        for name, value in named_objects.items():
            _write_private(output_path / name, canonical_bytes(value) + b"\n")
        manifest: JsonObject = {
            "schemaVersion": 2,
            "kind": "ordivon.security.evaluation-evidence-bundle",
            "runId": self.run_id,
            "evaluationSpecDigest": canonical_digest(evaluation_spec),
            "executionIdentityDigest": canonical_digest(execution_identity),
            "findingsDigest": canonical_digest(findings),
            "resultDigest": canonical_digest(result),
            "channels": channel_manifest,
            "artifacts": artifact_manifest,
        }
        _write_private(output_path / "bundle-manifest.json", canonical_bytes(manifest) + b"\n")
        semantic_digest = canonical_digest(manifest)

        operational_path = events_path / "operational.jsonl"
        operational_raw = b"".join(
            canonical_bytes(event.to_dict()) + b"\n" for event in self._operational_events
        )
        _write_private(operational_path, operational_raw)
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
        _write_private(
            output_path / "operational-manifest.json",
            canonical_bytes(operational_manifest) + b"\n",
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
    manifest = _load_object(
        resolve_relative_regular_file(
            path, "bundle-manifest.json", label="Evaluation bundle manifest"
        ),
        "Evaluation bundle manifest",
    )
    if manifest.get("schemaVersion") not in {1, 2}:
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
        raw = resolve_relative_regular_file(
            path, relative_path, label=f"Evaluation channel {channel.value}"
        ).read_bytes()
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

    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("Evaluation Artifact manifest must be a list")
    for metadata in artifacts:
        if not isinstance(metadata, dict):
            raise ValueError("Evaluation Artifact metadata must be an object")
        relative_path = metadata.get("path")
        if not isinstance(relative_path, str):
            raise ValueError("Evaluation Artifact path is invalid")
        artifact_path = resolve_relative_regular_file(
            path, relative_path, label="Evaluation Artifact"
        )
        digest, byte_length = _digest_path(artifact_path)
        if digest != metadata.get("digest") or byte_length != metadata.get("byteLength"):
            raise ValueError("Evaluation Artifact digest or byte length differs")

    named = (
        ("evaluation-spec.json", "evaluationSpecDigest"),
        ("execution-identity.json", "executionIdentityDigest"),
        ("findings.json", "findingsDigest"),
        ("result.json", "resultDigest"),
    )
    for filename, digest_field in named:
        value = _load_object(
            resolve_relative_regular_file(path, filename, label=filename), filename
        )
        if canonical_digest(value) != manifest.get(digest_field):
            raise ValueError(f"Evaluation object digest differs: {filename}")
    return canonical_digest(manifest)


def verify_evaluation_operational_evidence(path: Path) -> str:
    semantic_digest = verify_evaluation_evidence(path)
    manifest = _load_object(
        resolve_relative_regular_file(
            path,
            "operational-manifest.json",
            label="Evaluation operational evidence manifest",
        ),
        "Evaluation operational evidence manifest",
    )
    if manifest.get("semanticEvidenceDigest") != semantic_digest:
        raise ValueError("Evaluation operational evidence binds another semantic bundle")
    run_id = manifest.get("runId")
    relative_path = manifest.get("path")
    if not isinstance(run_id, str) or not isinstance(relative_path, str):
        raise ValueError("Evaluation operational identity or path is invalid")
    raw = resolve_relative_regular_file(
        path, relative_path, label="Evaluation operational evidence"
    ).read_bytes()
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
