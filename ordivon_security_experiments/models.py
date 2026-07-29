"""Stable experiment records, intentionally smaller than a Security ontology."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


def canonical_json(value: Any) -> str:
    """Return deterministic UTF-8 JSON suitable for evidence digests."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_json(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


@dataclass(frozen=True)
class ActorIdentity:
    actor_id: str
    role: str
    policy_type: str
    implementation: str
    model: str | None = None
    scaffold_revision: str | None = None
    tool_catalog_revision: str | None = None
    memory_mode: str = "none"
    resource_budget: Mapping[str, JsonValue] = field(default_factory=dict)
    organization_id: str | None = None


@dataclass(frozen=True)
class WorldIdentity:
    world_id: str
    adapter: str
    revision: str
    scenario: str
    configuration: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationIdentity:
    judge_id: str
    revision: str
    hidden_state_policy: str = "actor-inaccessible"


@dataclass(frozen=True)
class ExperimentSpec:
    experiment_id: str
    world: WorldIdentity
    actor: ActorIdentity
    evaluation: EvaluationIdentity
    seeds: tuple[int, ...]
    opponent_policies: tuple[str, ...]
    max_turns: int
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.experiment_id:
            raise ValueError("experiment_id is required")
        if not self.seeds:
            raise ValueError("at least one seed is required")
        if not self.opponent_policies:
            raise ValueError("at least one opponent policy is required")
        if self.max_turns < 1:
            raise ValueError("max_turns must be positive")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ExperimentSpec":
        return cls(
            experiment_id=str(raw["experiment_id"]),
            world=WorldIdentity(**raw["world"]),
            actor=ActorIdentity(**raw["actor"]),
            evaluation=EvaluationIdentity(**raw["evaluation"]),
            seeds=tuple(int(seed) for seed in raw["seeds"]),
            opponent_policies=tuple(str(policy) for policy in raw["opponent_policies"]),
            max_turns=int(raw["max_turns"]),
            metadata=dict(raw.get("metadata", {})),
        )

    @classmethod
    def from_path(cls, path: Path) -> "ExperimentSpec":
        return cls.from_dict(json.loads(path.read_text()))


@dataclass(frozen=True)
class Observation:
    observation_id: str
    trial_id: str
    turn: int
    actor_id: str
    visible_state: Mapping[str, JsonValue]
    allowed_actions: tuple[str, ...]
    source_truth_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Decision:
    action: str
    rationale: str = ""
    strategic_revision: Mapping[str, JsonValue] | None = None
    hypothesis_updates: tuple[Mapping[str, JsonValue], ...] = ()
    raw_response: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TrialOutcome:
    validity: float
    tactical: float
    operational: float
    strategic: float
    information: float
    organization: float
    evaluator_integrity: float
    cost: float
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "validity",
            "tactical",
            "operational",
            "strategic",
            "information",
            "organization",
            "evaluator_integrity",
        ):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.cost < 0:
            raise ValueError("cost cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TrialResult:
    trial_id: str
    experiment_id: str
    seed: int
    opponent_policy: str
    actor_identity: ActorIdentity
    world_identity: WorldIdentity
    evaluation_identity: EvaluationIdentity
    trace_digest: str
    event_count: int
    outcome: TrialOutcome
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FamilySummary:
    experiment_id: str
    trial_count: int
    groups: Mapping[str, Mapping[str, JsonValue]]
    trial_result_digests: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_probability_mapping(values: Mapping[str, float], *, names: Sequence[str]) -> None:
    for name in names:
        if name not in values:
            raise ValueError(f"missing metric {name}")
        if not 0.0 <= float(values[name]) <= 1.0:
            raise ValueError(f"metric {name} must be between 0 and 1")
