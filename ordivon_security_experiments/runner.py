"""Experiment execution and family aggregation."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import statistics
from typing import Any, Iterable, Mapping

from .interfaces import Actor, WorldAdapter
from .models import (
    ExperimentSpec,
    FamilySummary,
    TrialResult,
    digest_json,
    write_json,
)
from .trace import TraceEvent, TraceRecorder

_METRICS = (
    "validity",
    "tactical",
    "operational",
    "strategic",
    "information",
    "organization",
    "evaluator_integrity",
    "cost",
)


def run_trial(
    *,
    spec: ExperimentSpec,
    world: WorldAdapter,
    actor: Actor,
    seed: int,
    opponent_policy: str,
    output_dir: Path,
) -> TrialResult:
    trial_id = f"{spec.experiment_id}:{actor.identity.actor_id}:{opponent_policy}:seed-{seed}"
    trial_dir = output_dir / "trials" / _safe_name(trial_id)
    trial_dir.mkdir(parents=True, exist_ok=True)
    recorder = TraceRecorder(trial_dir / "trace.jsonl")

    world.reset(trial_id=trial_id, seed=seed, opponent_policy=opponent_policy)
    actor.reset(trial_id=trial_id, seed=seed, opponent_policy=opponent_policy)

    turn = 0
    while turn < spec.max_turns and not world.done():
        observation = world.observe(actor.identity.actor_id)
        decision = actor.decide(observation)
        effect = world.step(actor.identity.actor_id, decision)
        actor.update(observation, decision, effect)
        event = TraceEvent(
            event_id=f"{trial_id}:event-{turn + 1}",
            trial_id=trial_id,
            turn=observation.turn,
            actor_id=actor.identity.actor_id,
            observation=observation,
            decision=decision,
            effect=effect,
            world_truth_digest=digest_json(world.truth()),
        )
        recorder.append(event)
        turn += 1

    if not recorder.verify():
        raise RuntimeError(f"trace verification failed for {trial_id}")

    outcome = world.judge(actor_usage=actor.usage())
    result = TrialResult(
        trial_id=trial_id,
        experiment_id=spec.experiment_id,
        seed=seed,
        opponent_policy=opponent_policy,
        actor_identity=actor.identity,
        world_identity=world.identity,
        evaluation_identity=spec.evaluation,
        trace_digest=recorder.digest(),
        event_count=recorder.count,
        outcome=outcome,
        metadata={
            "world": dict(world.metadata()),
            "actor_usage": dict(actor.usage()),
            "spec_digest": digest_json(spec.to_dict()),
        },
    )
    write_json(trial_dir / "result.json", result.to_dict())
    return result


def run_family(
    *,
    spec: ExperimentSpec,
    world_factory: Any,
    actor_factory: Any,
    output_dir: Path,
) -> FamilySummary:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "experiment-spec.json", spec.to_dict())
    results: list[TrialResult] = []
    for opponent_policy in spec.opponent_policies:
        for seed in spec.seeds:
            world = world_factory()
            actor = actor_factory()
            result = run_trial(
                spec=spec,
                world=world,
                actor=actor,
                seed=seed,
                opponent_policy=opponent_policy,
                output_dir=output_dir,
            )
            results.append(result)

    groups = _aggregate(results)
    summary = FamilySummary(
        experiment_id=spec.experiment_id,
        trial_count=len(results),
        groups=groups,
        trial_result_digests=tuple(digest_json(result.to_dict()) for result in results),
    )
    write_json(output_dir / "summary.json", summary.to_dict())
    write_json(output_dir / "trial-index.json", [result.to_dict() for result in results])
    return summary


def _aggregate(results: Iterable[TrialResult]) -> dict[str, Mapping[str, Any]]:
    grouped: dict[str, list[TrialResult]] = {}
    for result in results:
        grouped.setdefault(result.opponent_policy, []).append(result)
    grouped["__all__"] = list(results)

    output: dict[str, Mapping[str, Any]] = {}
    for name, group in grouped.items():
        metrics: dict[str, Any] = {"trial_count": len(group)}
        for metric in _METRICS:
            values = [float(getattr(item.outcome, metric)) for item in group]
            metrics[metric] = {
                "mean": statistics.fmean(values),
                "min": min(values),
                "max": max(values),
                "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            }
        output[name] = metrics
    return output


def _safe_name(value: str) -> str:
    return "".join(character if character.isalnum() or character in "-_." else "_" for character in value)
