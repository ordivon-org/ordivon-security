"""Thin CAGE Challenge 4 baseline adapter.

CAGE 4 remains an external source tree. This module records only the facts needed
for substrate comparison and does not copy or reinterpret the full simulator.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import importlib
import json
from pathlib import Path
import statistics
import sys
from typing import Any, Mapping, Sequence

from .models import canonical_json, write_json

CAGE4_REPOSITORY = "https://github.com/cage-challenge/cage-challenge-4.git"
CAGE4_REVISION = "8c3c50ca54b176c2de199847944e8dcc035497e3"


@dataclass(frozen=True)
class Cage4BaselineSpec:
    experiment_id: str
    source_path: str
    source_revision: str
    seeds: tuple[int, ...]
    steps: int
    blue_policies: tuple[str, ...]
    red_policies: tuple[str, ...]


@dataclass(frozen=True)
class Cage4TrialResult:
    trial_id: str
    seed: int
    blue_policy: str
    red_policy: str
    source_revision: str
    step_count: int
    cumulative_blue_reward: float
    final_red_foothold_hosts: int
    maximum_red_foothold_hosts: int
    mission_phases_seen: tuple[int, ...]
    action_counts: Mapping[str, int]
    trace_digest: str


def run_cage4_baselines(spec: Cage4BaselineSpec, output_dir: Path) -> dict[str, Any]:
    _activate_source(Path(spec.source_path), spec.source_revision)
    imports = _load_cage4()
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "experiment-spec.json", asdict(spec))

    results: list[Cage4TrialResult] = []
    for blue_policy in spec.blue_policies:
        for red_policy in spec.red_policies:
            for seed in spec.seeds:
                result = _run_trial(
                    experiment_id=spec.experiment_id,
                    seed=seed,
                    steps=spec.steps,
                    blue_policy=blue_policy,
                    red_policy=red_policy,
                    source_revision=spec.source_revision,
                    output_dir=output_dir,
                    imports=imports,
                )
                results.append(result)

    summary = _summarize(results)
    write_json(output_dir / "trial-index.json", [asdict(result) for result in results])
    write_json(output_dir / "summary.json", summary)
    return summary


def _activate_source(source_path: Path, expected_revision: str) -> None:
    if not source_path.exists():
        raise FileNotFoundError(
            f"CAGE 4 source not found at {source_path}; run scripts/bootstrap_cage4.sh"
        )
    head_path = source_path / ".git" / "HEAD"
    if not head_path.exists():
        raise ValueError(f"{source_path} is not a Git checkout")
    import subprocess

    actual = subprocess.run(
        ["git", "-C", str(source_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual != expected_revision:
        raise ValueError(f"CAGE 4 revision mismatch: expected {expected_revision}, got {actual}")
    sys.path.insert(0, str(source_path))


def _load_cage4() -> dict[str, Any]:
    cyborg_module = importlib.import_module("CybORG")
    agents = importlib.import_module("CybORG.Agents")
    scenarios = importlib.import_module("CybORG.Simulator.Scenarios")
    return {
        "CybORG": getattr(cyborg_module, "CybORG"),
        "SleepAgent": getattr(agents, "SleepAgent"),
        "cc4BlueRandomAgent": getattr(agents, "cc4BlueRandomAgent"),
        "EnterpriseGreenAgent": getattr(agents, "EnterpriseGreenAgent"),
        "FiniteStateRedAgent": getattr(agents, "FiniteStateRedAgent"),
        "RandomSelectRedAgent": getattr(agents, "RandomSelectRedAgent"),
        "EnterpriseScenarioGenerator": getattr(scenarios, "EnterpriseScenarioGenerator"),
    }


def _run_trial(
    *,
    experiment_id: str,
    seed: int,
    steps: int,
    blue_policy: str,
    red_policy: str,
    source_revision: str,
    output_dir: Path,
    imports: Mapping[str, Any],
) -> Cage4TrialResult:
    blue_class = {
        "sleep": imports["SleepAgent"],
        "random": imports["cc4BlueRandomAgent"],
    }[blue_policy]
    red_class = {
        "finite-state": imports["FiniteStateRedAgent"],
        "random-select": imports["RandomSelectRedAgent"],
    }[red_policy]
    scenario = imports["EnterpriseScenarioGenerator"](
        blue_agent_class=blue_class,
        green_agent_class=imports["EnterpriseGreenAgent"],
        red_agent_class=red_class,
        steps=steps,
    )
    environment = imports["CybORG"](scenario_generator=scenario, seed=seed)
    trial_id = f"{experiment_id}:{blue_policy}:{red_policy}:seed-{seed}"
    trace_path = output_dir / "trials" / _safe_name(trial_id) / "trace.jsonl"
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_path.write_text("")
    hasher = sha256()
    cumulative_reward = 0.0
    maximum_footholds = 0
    phases: set[int] = set()
    action_counts: dict[str, int] = {}

    for turn in range(steps):
        observations, rewards, dones, _ = environment.parallel_step()
        state = environment.environment_controller.state
        phases.add(int(state.mission_phase))
        footholds = _red_foothold_hosts(state.hosts)
        maximum_footholds = max(maximum_footholds, footholds)
        blue_reward = sum(
            sum(float(value) for value in reward.values())
            for actor, reward in rewards.items()
            if actor.startswith("blue_agent_")
        )
        cumulative_reward += blue_reward
        actions = _action_names(environment.environment_controller.action)
        for action in actions.values():
            action_counts[action] = action_counts.get(action, 0) + 1
        event = {
            "trial_id": trial_id,
            "turn": turn + 1,
            "mission_phase": int(state.mission_phase),
            "blue_reward": blue_reward,
            "red_foothold_hosts": footholds,
            "actions": actions,
            "observation_actor_count": len(observations),
            "done_actor_count": sum(bool(value) for value in dones.values()),
            "world_truth_digest": _state_digest(state),
        }
        line = canonical_json(event) + "\n"
        with trace_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        hasher.update(line.encode("utf-8"))

    result = Cage4TrialResult(
        trial_id=trial_id,
        seed=seed,
        blue_policy=blue_policy,
        red_policy=red_policy,
        source_revision=source_revision,
        step_count=steps,
        cumulative_blue_reward=cumulative_reward,
        final_red_foothold_hosts=_red_foothold_hosts(environment.environment_controller.state.hosts),
        maximum_red_foothold_hosts=maximum_footholds,
        mission_phases_seen=tuple(sorted(phases)),
        action_counts=dict(sorted(action_counts.items())),
        trace_digest="sha256:" + hasher.hexdigest(),
    )
    write_json(trace_path.parent / "result.json", asdict(result))
    return result


def _red_foothold_hosts(hosts: Mapping[str, Any]) -> int:
    count = 0
    for host in hosts.values():
        sessions = getattr(host, "sessions", {})
        if any(name.startswith("red_agent_") and identifiers for name, identifiers in sessions.items()):
            count += 1
    return count


def _action_names(actions: Mapping[str, Any]) -> dict[str, str]:
    output: dict[str, str] = {}
    for actor, action_list in actions.items():
        if not action_list:
            output[actor] = "None"
        elif isinstance(action_list, list):
            output[actor] = "+".join(type(action).__name__ for action in action_list)
        else:
            output[actor] = type(action_list).__name__
    return output


def _state_digest(state: Any) -> str:
    native_time = state.time.isoformat() if hasattr(state.time, "isoformat") else str(state.time)
    session_count = state.sessions_count
    if isinstance(session_count, Mapping):
        session_count = sum(len(value) if hasattr(value, "__len__") else int(value) for value in session_count.values())
    summary = {
        "native_time": native_time,
        "mission_phase": int(state.mission_phase),
        "host_count": len(state.hosts),
        "red_foothold_hosts": _red_foothold_hosts(state.hosts),
        "block_count": len(state.blocks),
        "session_count": int(session_count),
    }
    return "sha256:" + sha256(canonical_json(summary).encode("utf-8")).hexdigest()


def _summarize(results: Sequence[Cage4TrialResult]) -> dict[str, Any]:
    groups: dict[str, list[Cage4TrialResult]] = {}
    for result in results:
        key = f"blue={result.blue_policy}|red={result.red_policy}"
        groups.setdefault(key, []).append(result)
    summary_groups: dict[str, Any] = {}
    for key, group in sorted(groups.items()):
        rewards = [result.cumulative_blue_reward for result in group]
        footholds = [float(result.maximum_red_foothold_hosts) for result in group]
        summary_groups[key] = {
            "trial_count": len(group),
            "cumulative_blue_reward": _distribution(rewards),
            "maximum_red_foothold_hosts": _distribution(footholds),
            "mission_phases_seen": sorted({phase for result in group for phase in result.mission_phases_seen}),
        }
    return {
        "kind": "ordivon-cage4-substrate-comparison",
        "source_repository": CAGE4_REPOSITORY,
        "source_revision": results[0].source_revision if results else None,
        "trial_count": len(results),
        "groups": summary_groups,
    }


def _distribution(values: Sequence[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


def _safe_name(value: str) -> str:
    return "".join(character if character.isalnum() or character in "-_." else "_" for character in value)
