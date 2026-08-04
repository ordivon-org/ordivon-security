from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json


def _text(value: str, label: str, *, prefix: str | None = None) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty and trimmed")
    if len(value.encode("utf-8")) > 300:
        raise ValueError(f"{label} exceeds 300 UTF-8 bytes")
    if prefix is not None and not value.startswith(prefix + ":"):
        raise ValueError(f"{label} must start with {prefix}:")
    return value


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} values must be unique")
    for value in values:
        _text(value, label)


@dataclass(frozen=True, slots=True)
class ActorBinding:
    actor_id: str
    side: str
    backend_id: str
    backend_config_digest: str
    objective: str
    allowed_actions: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.actor_id, "Actor identity", prefix="actor")
        _text(self.side, "Actor side")
        _text(self.backend_id, "Actor backend identity", prefix="backend")
        _text(self.backend_config_digest, "Actor backend configuration digest", prefix="sha256")
        _text(self.objective, "Actor objective")
        _unique(self.allowed_actions, "Actor action")
        if not self.allowed_actions:
            raise ValueError("Actor must have at least one allowed action")

    def to_dict(self) -> JsonObject:
        return {
            "actorId": self.actor_id,
            "side": self.side,
            "backendId": self.backend_id,
            "backendConfigDigest": self.backend_config_digest,
            "objective": self.objective,
            "allowedActions": list(self.allowed_actions),
        }


@dataclass(frozen=True, slots=True)
class ScenarioManifest:
    scenario_id: str
    revision: str
    range_id: str
    actors: tuple[ActorBinding, ...]
    max_ticks: int
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.scenario_id, "Scenario identity", prefix="scenario")
        _text(self.revision, "Scenario revision")
        _text(self.range_id, "Range identity", prefix="range")
        if len(self.actors) < 2:
            raise ValueError("Contest requires at least two actors")
        actor_ids = tuple(actor.actor_id for actor in self.actors)
        _unique(actor_ids, "Scenario Actor identity")
        if self.max_ticks < 1:
            raise ValueError("Scenario max ticks must be positive")
        validate_json(self.metadata)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def actor(self, actor_id: str) -> ActorBinding:
        for actor in self.actors:
            if actor.actor_id == actor_id:
                return actor
        raise KeyError(actor_id)

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.scenario-manifest",
            "scenarioId": self.scenario_id,
            "revision": self.revision,
            "rangeId": self.range_id,
            "actors": [actor.to_dict() for actor in self.actors],
            "maxTicks": self.max_ticks,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class ActorObservation:
    actor_id: str
    tick: int
    visible_state: JsonObject
    allowed_actions: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.actor_id, "Observation Actor identity", prefix="actor")
        if self.tick < 0:
            raise ValueError("Observation tick must be non-negative")
        validate_json(self.visible_state)
        _unique(self.allowed_actions, "Observation action")

    def to_dict(self) -> JsonObject:
        return {
            "actorId": self.actor_id,
            "tick": self.tick,
            "visibleState": self.visible_state,
            "allowedActions": list(self.allowed_actions),
        }


@dataclass(frozen=True, slots=True)
class ActionProposal:
    proposal_id: str
    actor_id: str
    tick: int
    action_type: str
    target_refs: tuple[str, ...] = ()
    arguments: JsonObject = field(default_factory=dict)
    objective_refs: tuple[str, ...] = ()
    authority_refs: tuple[str, ...] = ()
    rationale: str | None = None

    def __post_init__(self) -> None:
        _text(self.proposal_id, "Proposal identity", prefix="proposal")
        _text(self.actor_id, "Proposal Actor identity", prefix="actor")
        if self.tick < 0:
            raise ValueError("Proposal tick must be non-negative")
        _text(self.action_type, "Proposal action type")
        _unique(self.target_refs, "Proposal target")
        _unique(self.objective_refs, "Proposal objective reference")
        _unique(self.authority_refs, "Proposal authority reference")
        validate_json(self.arguments)
        if self.rationale is not None:
            _text(self.rationale, "Proposal rationale")

    def to_dict(self) -> JsonObject:
        return {
            "proposalId": self.proposal_id,
            "actorId": self.actor_id,
            "tick": self.tick,
            "actionType": self.action_type,
            "targetRefs": list(self.target_refs),
            "arguments": self.arguments,
            "objectiveRefs": list(self.objective_refs),
            "authorityRefs": list(self.authority_refs),
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class ActionAdmission:
    proposal: ActionProposal
    admitted: bool
    reason: str

    def __post_init__(self) -> None:
        _text(self.reason, "Admission reason")

    def to_dict(self) -> JsonObject:
        return {
            "proposal": self.proposal.to_dict(),
            "admitted": self.admitted,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ActorActionResult:
    proposal_id: str
    actor_id: str
    tick: int
    status: str
    effects: tuple[str, ...] = ()
    observation: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.proposal_id, "Action result proposal identity", prefix="proposal")
        _text(self.actor_id, "Action result Actor identity", prefix="actor")
        if self.tick < 0:
            raise ValueError("Action result tick must be non-negative")
        _text(self.status, "Action result status")
        _unique(self.effects, "Action result effect")
        validate_json(self.observation)

    def to_dict(self) -> JsonObject:
        return {
            "proposalId": self.proposal_id,
            "actorId": self.actor_id,
            "tick": self.tick,
            "status": self.status,
            "effects": list(self.effects),
            "observation": self.observation,
        }


@dataclass(frozen=True, slots=True)
class WorldTruthSnapshot:
    tick: int
    state: JsonObject

    def __post_init__(self) -> None:
        if self.tick < 0:
            raise ValueError("World truth tick must be non-negative")
        validate_json(self.state)

    def to_dict(self) -> JsonObject:
        return {"tick": self.tick, "state": self.state}


@dataclass(frozen=True, slots=True)
class RangeResolution:
    tick: int
    results: tuple[ActorActionResult, ...]
    sensor_events: tuple[JsonObject, ...] = ()

    def __post_init__(self) -> None:
        if self.tick < 0:
            raise ValueError("Resolution tick must be non-negative")
        proposal_ids = tuple(result.proposal_id for result in self.results)
        _unique(proposal_ids, "Resolution proposal identity")
        for event in self.sensor_events:
            validate_json(event)

    def to_dict(self) -> JsonObject:
        return {
            "tick": self.tick,
            "results": [result.to_dict() for result in self.results],
            "sensorEvents": list(self.sensor_events),
        }


@dataclass(frozen=True, slots=True)
class ContestResult:
    trial_id: str
    scenario_digest: str
    seed: int
    terminal_reason: str
    ticks_executed: int
    raw_metrics: JsonObject
    evidence_path: str
    evidence_digest: str

    def __post_init__(self) -> None:
        _text(self.trial_id, "Trial identity", prefix="trial")
        _text(self.scenario_digest, "Scenario digest", prefix="sha256")
        _text(self.terminal_reason, "Contest terminal reason")
        if self.seed < 0 or self.ticks_executed < 0:
            raise ValueError("Contest seed and tick count must be non-negative")
        validate_json(self.raw_metrics)
        _text(self.evidence_path, "Evidence path")
        _text(self.evidence_digest, "Evidence digest", prefix="sha256")

    def to_dict(self) -> JsonObject:
        return {
            "trialId": self.trial_id,
            "scenarioDigest": self.scenario_digest,
            "seed": self.seed,
            "terminalReason": self.terminal_reason,
            "ticksExecuted": self.ticks_executed,
            "rawMetrics": self.raw_metrics,
            "evidencePath": self.evidence_path,
            "evidenceDigest": self.evidence_digest,
        }


def json_object(value: dict[str, Any]) -> JsonObject:
    validate_json(value)
    return value
