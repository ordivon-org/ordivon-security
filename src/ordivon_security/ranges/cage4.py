from __future__ import annotations

import importlib
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.contest.model import (
    ActionAdmission,
    ActionProposal,
    ActorActionResult,
    ActorObservation,
    RangeResolution,
    ScenarioManifest,
    WorldTruthSnapshot,
    json_object,
)
from ordivon_security.identity import security_source_identity

from .protocol import RangeDestroyReceipt, RangeInstance, RangeTerminal

CAGE4_REPOSITORY = "https://github.com/cage-challenge/cage-challenge-4.git"
CAGE4_REVISION = "8c3c50ca54b176c2de199847944e8dcc035497e3"
CAGE4_RANGE_ID = "range:cage4-enterprise-v1"
CAGE4_NATIVE_PLAN = "cage.team.native-policy"
CAGE4_SLEEP_PLAN = "cage.team.sleep"
CAGE4_PLANS = (CAGE4_NATIVE_PLAN, CAGE4_SLEEP_PLAN)


@dataclass(frozen=True, slots=True)
class Cage4RangeConfig:
    source_path: str
    source_revision: str = CAGE4_REVISION
    source_repository: str = CAGE4_REPOSITORY
    blue_policy: str = "cc4-random"
    red_policy: str = "finite-state"

    def __post_init__(self) -> None:
        if not self.source_path:
            raise ValueError("CAGE 4 source path must be non-empty")
        if self.source_revision != CAGE4_REVISION:
            raise ValueError(
                f"unsupported CAGE 4 revision: {self.source_revision}; expected {CAGE4_REVISION}"
            )
        if self.blue_policy != "cc4-random":
            raise ValueError("the first CAGE 4 adapter supports cc4-random Blue only")
        if self.red_policy != "finite-state":
            raise ValueError("the first CAGE 4 adapter supports finite-state Red only")

    @property
    def digest(self) -> str:
        return canonical_digest(self.identity_dict())

    def identity_dict(self) -> JsonObject:
        return {
            "sourceRevision": self.source_revision,
            "sourceRepository": self.source_repository,
            "bluePolicy": self.blue_policy,
            "redPolicy": self.red_policy,
        }

    def to_dict(self) -> JsonObject:
        return {**self.identity_dict(), "sourcePath": self.source_path}


@dataclass(slots=True)
class _Cage4State:
    manifest: ScenarioManifest
    environment: Any
    imports: dict[str, Any]
    team_agents: dict[str, tuple[str, ...]]
    tick: int = 0
    cumulative_rewards: dict[str, float] = field(default_factory=lambda: {"red": 0.0, "blue": 0.0})
    maximum_red_footholds: int = 0
    mission_phases: set[int] = field(default_factory=lambda: {0})
    action_counts: dict[str, int] = field(default_factory=dict)
    externally_submitted_actions: int = 0
    last_team_rewards: dict[str, float] = field(default_factory=lambda: {"red": 0.0, "blue": 0.0})


class Cage4RangeBackend:
    """Pinned CAGE Challenge 4 Enterprise Scenario as an authoritative Range.

    Red and Blue actions are always supplied explicitly by Ordivon. The first
    adapter exposes two team plans: invoke the pinned CAGE policy or force Sleep.
    Green agents remain CAGE-controlled environmental actors.
    """

    range_id = CAGE4_RANGE_ID

    def __init__(self, config: Cage4RangeConfig) -> None:
        self.config = config
        self._states: dict[str, _Cage4State] = {}

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "rangeId": self.range_id,
            "adapterRevision": "cage4-team-plan-adapter-v2",
            "adapterImplementation": security_source_identity(),
            "substrate": self.config.identity_dict(),
            "rangeConfigDigest": self.config.digest,
        }

    def create(self, trial_id: str, manifest: ScenarioManifest, seed: int) -> RangeInstance:
        if manifest.range_id != self.range_id:
            raise ValueError("Scenario targets another Range")
        sides = {actor.side for actor in manifest.actors}
        if sides != {"red", "blue"} or len(manifest.actors) != 2:
            raise ValueError("CAGE 4 Range requires exactly one Red and one Blue Security Actor")
        expected_revision = manifest.metadata.get("cage4SourceRevision")
        if expected_revision != self.config.source_revision:
            raise ValueError("Scenario CAGE source revision differs from Range configuration")
        expected_config = manifest.metadata.get("cage4RangeConfigDigest")
        if expected_config != self.config.digest:
            raise ValueError("Scenario CAGE Range configuration digest differs")

        imports = _load_cage4(Path(self.config.source_path), self.config.source_revision)
        scenario = imports["EnterpriseScenarioGenerator"](
            blue_agent_class=imports["cc4BlueRandomAgent"],
            green_agent_class=imports["EnterpriseGreenAgent"],
            red_agent_class=imports["FiniteStateRedAgent"],
            # Pinned CAGE 4 marks done when step_count >= steps - 1. Add one so
            # Security's max_ticks remains the number of executable Contest ticks.
            steps=manifest.max_ticks + 1,
        )
        environment = imports["CybORG"](scenario_generator=scenario, seed=seed)
        team_agents = {
            "red": tuple(
                sorted(a for a in environment.active_agents if a.startswith("red_agent_"))
            ),
            "blue": tuple(
                sorted(a for a in environment.active_agents if a.startswith("blue_agent_"))
            ),
        }
        if not team_agents["red"] or not team_agents["blue"]:
            raise ValueError("CAGE 4 did not create both Red and Blue agents")

        instance = RangeInstance(
            instance_id=f"range-instance:{trial_id.removeprefix('trial:')}",
            trial_id=trial_id,
        )
        if instance.instance_id in self._states:
            raise ValueError("Range instance already exists")
        state = _Cage4State(
            manifest=manifest,
            environment=environment,
            imports=imports,
            team_agents=team_agents,
        )
        state.maximum_red_footholds = _red_foothold_hosts(
            environment.environment_controller.state.hosts
        )
        self._states[instance.instance_id] = state
        return instance

    def observe(self, instance: RangeInstance, actor_id: str) -> ActorObservation:
        state = self._state(instance)
        binding = state.manifest.actor(actor_id)
        if binding.side not in state.team_agents:
            raise ValueError(f"unsupported CAGE team side: {binding.side}")
        environment = state.environment
        agent_observations = {
            agent: _jsonify(environment.get_observation(agent))
            for agent in state.team_agents[binding.side]
        }
        action_spaces = {
            agent: _action_space_summary(environment.get_action_space(agent))
            for agent in state.team_agents[binding.side]
        }
        visible_state = json_object(
            {
                "range": self.range_id,
                "sourceRevision": self.config.source_revision,
                "team": binding.side,
                "tick": state.tick,
                "missionPhase": int(environment.environment_controller.state.mission_phase),
                "controlledAgents": list(state.team_agents[binding.side]),
                "planOptions": list(CAGE4_PLANS),
                "agentObservations": agent_observations,
                "actionSpaceSummary": action_spaces,
                "lastTeamReward": state.last_team_rewards[binding.side],
            }
        )
        return ActorObservation(
            actor_id=actor_id,
            tick=state.tick,
            visible_state=visible_state,
            allowed_actions=binding.allowed_actions,
        )

    def admit(self, instance: RangeInstance, proposal: ActionProposal) -> ActionAdmission:
        state = self._state(instance)
        try:
            binding = state.manifest.actor(proposal.actor_id)
        except KeyError:
            return ActionAdmission(proposal, False, "unknown-actor")
        if proposal.tick != state.tick:
            return ActionAdmission(proposal, False, "tick-drift")
        if proposal.action_type not in binding.allowed_actions:
            return ActionAdmission(proposal, False, "action-not-granted")
        if proposal.action_type not in CAGE4_PLANS:
            return ActionAdmission(proposal, False, "unsupported-cage-team-plan")
        return ActionAdmission(proposal, True, "admitted")

    def resolve(
        self,
        instance: RangeInstance,
        admissions: tuple[ActionAdmission, ...],
    ) -> RangeResolution:
        state = self._state(instance)
        plans: dict[str, tuple[ActionProposal, str]] = {}
        for admission in admissions:
            if not admission.admitted:
                continue
            proposal = admission.proposal
            side = state.manifest.actor(proposal.actor_id).side
            if side in plans:
                raise ValueError("CAGE 4 accepts one proposal per Security side and tick")
            plans[side] = (proposal, proposal.action_type)
        if set(plans) != {"red", "blue"}:
            raise ValueError("CAGE 4 requires admitted Red and Blue plans on every tick")

        environment = state.environment
        controller = environment.environment_controller
        action_dict: dict[str, Any] = {}
        action_names: dict[str, str] = {}
        for side in ("red", "blue"):
            _, plan = plans[side]
            for cage_agent in state.team_agents[side]:
                if plan == CAGE4_SLEEP_PLAN:
                    action = state.imports["Sleep"]()
                else:
                    interface = controller.agent_interfaces[cage_agent]
                    action = interface.get_action(controller.get_last_observation(cage_agent))
                action_dict[cage_agent] = action
                action_name = type(action).__name__
                action_names[cage_agent] = action_name
                state.action_counts[action_name] = state.action_counts.get(action_name, 0) + 1

        expected_external_count = len(state.team_agents["red"]) + len(state.team_agents["blue"])
        if len(action_dict) != expected_external_count:
            raise RuntimeError("not every Red/Blue CAGE agent received an external action")
        observations, rewards, dones, _ = environment.parallel_step(actions=action_dict)
        state.externally_submitted_actions += len(action_dict)
        state.tick += 1

        team_rewards = {
            side: sum(_reward_value(rewards.get(agent, {})) for agent in state.team_agents[side])
            for side in ("red", "blue")
        }
        for side, value in team_rewards.items():
            state.cumulative_rewards[side] += value
            state.last_team_rewards[side] = value
        native_state = controller.state
        phase = int(native_state.mission_phase)
        state.mission_phases.add(phase)
        footholds = _red_foothold_hosts(native_state.hosts)
        state.maximum_red_footholds = max(state.maximum_red_footholds, footholds)

        results: list[ActorActionResult] = []
        for side in ("red", "blue"):
            proposal, plan = plans[side]
            side_actions = {agent: action_names[agent] for agent in state.team_agents[side]}
            results.append(
                ActorActionResult(
                    proposal_id=proposal.proposal_id,
                    actor_id=proposal.actor_id,
                    tick=proposal.tick,
                    status="resolved",
                    effects=tuple(
                        f"cage-action-attempt:{agent}:{name}"
                        for agent, name in side_actions.items()
                    ),
                    observation=json_object(
                        {
                            "plan": plan,
                            "teamReward": team_rewards[side],
                            "actions": side_actions,
                            "done": all(
                                bool(dones.get(agent, False)) for agent in state.team_agents[side]
                            ),
                        }
                    ),
                )
            )

        sensor_event = json_object(
            {
                "kind": "cage-step-telemetry",
                "tick": state.tick,
                "missionPhase": phase,
                "teamRewards": team_rewards,
                "redFootholdHosts": footholds,
                "externallySubmittedActions": len(action_dict),
                "observationActorCount": len(observations),
            }
        )
        return RangeResolution(
            tick=state.tick - 1,
            results=tuple(sorted(results, key=lambda result: result.actor_id)),
            sensor_events=(sensor_event,),
        )

    def truth(self, instance: RangeInstance) -> WorldTruthSnapshot:
        state = self._state(instance)
        native = state.environment.environment_controller.state
        session_count = native.sessions_count
        if isinstance(session_count, Mapping):
            session_count = sum(
                len(value) if hasattr(value, "__len__") else int(value)
                for value in session_count.values()
            )
        return WorldTruthSnapshot(
            tick=state.tick,
            state={
                "sourceRevision": self.config.source_revision,
                "stepCount": int(state.environment.environment_controller.step_count),
                "missionPhase": int(native.mission_phase),
                "hostCount": len(native.hosts),
                "blockCount": len(native.blocks),
                "sessionCount": int(session_count),
                "redFootholdHosts": _red_foothold_hosts(native.hosts),
                "redAgentCount": len(state.team_agents["red"]),
                "blueAgentCount": len(state.team_agents["blue"]),
                "greenAgentCount": len(
                    [a for a in state.environment.active_agents if a.startswith("green_agent_")]
                ),
                "done": bool(state.environment.environment_controller.done),
            },
        )

    def metrics(self, instance: RangeInstance) -> JsonObject:
        state = self._state(instance)
        native = state.environment.environment_controller.state
        return json_object(
            {
                "cage.source.revision": self.config.source_revision,
                "cage.ticks": state.tick,
                "cage.native_episode_steps": state.manifest.max_ticks + 1,
                "cage.red.agent_count": len(state.team_agents["red"]),
                "cage.blue.agent_count": len(state.team_agents["blue"]),
                "cage.external_actions.submitted": state.externally_submitted_actions,
                "cage.default_red_blue_actions.used": 0,
                "cage.red.reward.cumulative": state.cumulative_rewards["red"],
                "cage.blue.reward.cumulative": state.cumulative_rewards["blue"],
                "cage.red.foothold_hosts.current": _red_foothold_hosts(native.hosts),
                "cage.red.foothold_hosts.maximum": state.maximum_red_footholds,
                "cage.mission_phases.seen": sorted(state.mission_phases),
                "cage.actions.counts": dict(sorted(state.action_counts.items())),
            }
        )

    def terminal(self, instance: RangeInstance) -> RangeTerminal:
        state = self._state(instance)
        if state.environment.environment_controller.done:
            return RangeTerminal(True, "cage-terminal")
        return RangeTerminal(False)

    def destroy(self, instance: RangeInstance) -> RangeDestroyReceipt:
        state = self._states.pop(instance.instance_id, None)
        return RangeDestroyReceipt(
            instance_id=instance.instance_id,
            status="destroyed" if state is not None else "already-absent",
            details={"retainedExternalState": False, "sourceRevision": self.config.source_revision},
        )

    def _state(self, instance: RangeInstance) -> _Cage4State:
        try:
            return self._states[instance.instance_id]
        except KeyError as error:
            raise KeyError(f"unknown CAGE 4 Range instance: {instance.instance_id}") from error


def _load_cage4(source_path: Path, expected_revision: str) -> dict[str, Any]:
    if not source_path.exists():
        raise FileNotFoundError(
            f"CAGE 4 source not found at {source_path}; run scripts/bootstrap_cage4.sh"
        )
    if not (source_path / ".git").exists():
        raise ValueError(f"{source_path} is not a Git checkout")
    actual = subprocess.run(
        ["git", "-C", str(source_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual != expected_revision:
        raise ValueError(f"CAGE 4 revision mismatch: expected {expected_revision}, got {actual}")
    dirty = subprocess.run(
        ["git", "-C", str(source_path), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if dirty:
        raise ValueError("CAGE 4 source tree must be clean")
    source_text = str(source_path.resolve())
    if source_text not in sys.path:
        sys.path.insert(0, source_text)
    cyborg_module = importlib.import_module("CybORG")
    module_source = cyborg_module.__file__
    if module_source is None:
        raise RuntimeError("CybORG module has no source file")
    module_file = Path(module_source).resolve()
    if source_path.resolve() not in module_file.parents:
        raise RuntimeError(f"CybORG was imported from an unexpected source: {module_file}")
    agents = importlib.import_module("CybORG.Agents")
    scenarios = importlib.import_module("CybORG.Simulator.Scenarios")
    actions = importlib.import_module("CybORG.Simulator.Actions")
    return {
        "CybORG": cyborg_module.CybORG,
        "cc4BlueRandomAgent": agents.cc4BlueRandomAgent,
        "EnterpriseGreenAgent": agents.EnterpriseGreenAgent,
        "FiniteStateRedAgent": agents.FiniteStateRedAgent,
        "EnterpriseScenarioGenerator": scenarios.EnterpriseScenarioGenerator,
        "Sleep": actions.Sleep,
    }


def _red_foothold_hosts(hosts: Mapping[str, Any]) -> int:
    count = 0
    for host in hosts.values():
        sessions = getattr(host, "sessions", {})
        if any(
            str(agent).startswith("red_agent_") and identifiers
            for agent, identifiers in sessions.items()
        ):
            count += 1
    return count


def _reward_value(reward: Any) -> float:
    if isinstance(reward, Mapping):
        return sum(float(value) for value in reward.values())
    if reward is None:
        return 0.0
    return float(reward)


def _action_space_summary(action_space: Mapping[str, Any]) -> JsonObject:
    actions = action_space.get("action", {})
    enabled_actions = sorted(
        action.__name__ if hasattr(action, "__name__") else str(action)
        for action, enabled in actions.items()
        if enabled
    )
    parameter_counts: JsonObject = {}
    for name, values in action_space.items():
        if name in {"action", "allowed_subnets"}:
            continue
        if isinstance(values, Mapping):
            parameter_counts[str(name)] = sum(bool(enabled) for enabled in values.values())
    allowed_subnets = action_space.get("allowed_subnets", ())
    return json_object(
        {
            "enabledActions": enabled_actions,
            "enabledParameterCounts": parameter_counts,
            "allowedSubnets": sorted(str(value) for value in allowed_subnets),
        }
    )


def _jsonify(value: Any) -> Any:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, Enum):
        return value.name
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonify(asdict(value))
    if isinstance(value, Mapping):
        return {
            str(key): _jsonify(item) for key, item in sorted(value.items(), key=lambda x: str(x[0]))
        }
    if isinstance(value, set | frozenset):
        return [_jsonify(item) for item in sorted(value, key=str)]
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_jsonify(item) for item in value]
    if hasattr(value, "item"):
        try:
            return _jsonify(value.item())
        except (TypeError, ValueError):
            pass
    if isinstance(value, type):
        return value.__name__
    return str(value)
