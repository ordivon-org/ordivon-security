from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json

from .models import EvaluationSpec, SampleIdentity


@dataclass(frozen=True, slots=True)
class ObserverRecord:
    channel: str
    event_type: str
    payload: JsonObject

    def __post_init__(self) -> None:
        if not self.channel or not self.event_type:
            raise ValueError("Observer record channel and event type must be non-empty")
        validate_json(self.payload)

    def to_dict(self) -> JsonObject:
        return {
            "channel": self.channel,
            "eventType": self.event_type,
            "payload": self.payload,
        }


@dataclass(frozen=True, slots=True)
class GuardianRecord:
    decision: str
    reason: str
    payload: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.decision not in {"allow", "terminate"}:
            raise ValueError("Guardian decision is unsupported")
        if not self.reason:
            raise ValueError("Guardian reason must be non-empty")
        validate_json(self.payload)

    def to_dict(self) -> JsonObject:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "payload": self.payload,
        }


@dataclass(frozen=True, slots=True)
class EvaluationArtifact:
    artifact_id: str
    kind: str
    digest: str
    byte_length: int

    def __post_init__(self) -> None:
        if not self.artifact_id.startswith("artifact:") or not self.kind:
            raise ValueError("Evaluation Artifact identity or kind is invalid")
        if not self.digest.startswith("sha256:") or self.byte_length < 0:
            raise ValueError("Evaluation Artifact digest or byte length is invalid")

    def to_dict(self) -> JsonObject:
        return {
            "artifactId": self.artifact_id,
            "kind": self.kind,
            "digest": self.digest,
            "byteLength": self.byte_length,
        }


@dataclass(slots=True)
class EvaluationInstance:
    instance_id: str
    generation: str
    state: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.instance_id.startswith("evaluation-instance:") or not self.generation:
            raise ValueError("Evaluation instance identity is invalid")
        validate_json(self.state)


@dataclass(frozen=True, slots=True)
class EvaluationExecution:
    terminal_reason: str
    observer_records: tuple[ObserverRecord, ...]
    guardian_records: tuple[GuardianRecord, ...]
    world_facts: JsonObject
    raw_metrics: JsonObject
    artifacts: tuple[EvaluationArtifact, ...] = ()

    def __post_init__(self) -> None:
        if not self.terminal_reason:
            raise ValueError("Evaluation execution terminal reason must be non-empty")
        validate_json(self.world_facts)
        validate_json(self.raw_metrics)


@dataclass(frozen=True, slots=True)
class ResidualClosureReceipt:
    clean: bool
    details: JsonObject

    def __post_init__(self) -> None:
        validate_json(self.details)

    def to_dict(self) -> JsonObject:
        return {"clean": self.clean, "details": self.details}


class EvaluationRangeBackend(Protocol):
    backend_id: str
    provider_id: str

    @property
    def execution_identity(self) -> JsonObject: ...

    def create(self, run_id: str, spec: EvaluationSpec) -> EvaluationInstance: ...

    def stage(
        self,
        instance: EvaluationInstance,
        sample_path: Path,
        sample: SampleIdentity,
    ) -> JsonObject: ...

    def execute(
        self,
        instance: EvaluationInstance,
        spec: EvaluationSpec,
    ) -> EvaluationExecution: ...

    def destroy(self, instance: EvaluationInstance) -> ResidualClosureReceipt: ...


class FixtureEvaluationBackend:
    """Deterministic local backend that never executes Sample bytes."""

    backend_id = "backend:evaluation-fixture"
    provider_id = "provider:evaluation-fixture"

    def __init__(
        self,
        *,
        observer_records: tuple[ObserverRecord, ...] = (),
        guardian_records: tuple[GuardianRecord, ...] = (),
        terminal_reason: str = "fixture-completed",
        world_facts: JsonObject | None = None,
        raw_metrics: JsonObject | None = None,
        residual_clean: bool = True,
        fail_phase: str | None = None,
    ) -> None:
        self.observer_records = observer_records
        self.guardian_records = guardian_records
        self.terminal_reason = terminal_reason
        self.world_facts = {} if world_facts is None else dict(world_facts)
        self.raw_metrics = {} if raw_metrics is None else dict(raw_metrics)
        self.residual_clean = residual_clean
        self.fail_phase = fail_phase
        self.create_calls = 0
        self.stage_calls = 0
        self.execute_calls = 0
        self.destroy_calls = 0

    @property
    def execution_identity(self) -> JsonObject:
        configuration: JsonObject = {
            "observerRecords": [record.to_dict() for record in self.observer_records],
            "guardianRecords": [record.to_dict() for record in self.guardian_records],
            "terminalReason": self.terminal_reason,
            "worldFacts": self.world_facts,
            "rawMetrics": self.raw_metrics,
            "residualClean": self.residual_clean,
            "failPhase": self.fail_phase,
        }
        return {
            "kind": "ordivon.security.evaluation-backend",
            "backendId": self.backend_id,
            "providerId": self.provider_id,
            "implementationRevision": "1",
            "configurationDigest": canonical_digest(configuration),
            "sampleExecution": False,
        }

    def _fail(self, phase: str) -> None:
        if self.fail_phase == phase:
            raise RuntimeError(f"fixture backend failure during {phase}")

    def create(self, run_id: str, spec: EvaluationSpec) -> EvaluationInstance:
        self.create_calls += 1
        self._fail("create")
        return EvaluationInstance(
            instance_id=f"evaluation-instance:{run_id.removeprefix('evaluation-run:')}",
            generation=f"fixture-generation:{spec.environment.configuration_digest[-16:]}",
        )

    def stage(
        self,
        instance: EvaluationInstance,
        sample_path: Path,
        sample: SampleIdentity,
    ) -> JsonObject:
        self.stage_calls += 1
        self._fail("stage")
        digest = hashlib.sha256(sample_path.read_bytes()).hexdigest()
        if f"sha256:{digest}" != sample.sha256:
            raise ValueError("Fixture stage received bytes outside the admitted Sample identity")
        instance.state["sampleDigest"] = sample.sha256
        return {
            "instanceId": instance.instance_id,
            "sampleId": sample.sample_id,
            "sampleDigest": sample.sha256,
            "executed": False,
        }

    def execute(
        self,
        instance: EvaluationInstance,
        spec: EvaluationSpec,
    ) -> EvaluationExecution:
        self.execute_calls += 1
        self._fail("execute")
        if instance.state.get("sampleDigest") != spec.sample.sha256:
            raise ValueError("Fixture Sample was not staged")
        return EvaluationExecution(
            terminal_reason=self.terminal_reason,
            observer_records=self.observer_records,
            guardian_records=self.guardian_records,
            world_facts=self.world_facts,
            raw_metrics={**self.raw_metrics, "fixture.sample_executed": False},
        )

    def destroy(self, instance: EvaluationInstance) -> ResidualClosureReceipt:
        self.destroy_calls += 1
        self._fail("destroy")
        instance.state["destroyed"] = True
        return ResidualClosureReceipt(
            clean=self.residual_clean,
            details={
                "instanceId": instance.instance_id,
                "generation": instance.generation,
                "sampleExecuted": False,
                "residualObjects": [] if self.residual_clean else ["fixture:residual"],
            },
        )
