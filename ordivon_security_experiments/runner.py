"""Experiment execution, immutable Trial evidence, and family aggregation."""

from __future__ import annotations

from pathlib import Path
import statistics
from typing import Any, Callable, Iterable, Mapping

from .evidence import (
    build_trial_manifest,
    discard_trial_staging,
    prepare_trial_staging,
    seal_and_commit_trial,
)
from .interfaces import Actor, Scorer, WorldAdapter
from .models import (
    ExperimentSpec,
    FamilySummary,
    HiddenEvaluationRecord,
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
    scorer: Scorer,
    seed: int,
    opponent_policy: str,
    output_dir: Path,
) -> TrialResult:
    if actor.identity != spec.actor:
        raise ValueError("Actor identity differs from the admitted ExperimentSpec")
    if world.identity != spec.world:
        raise ValueError("World identity differs from the admitted ExperimentSpec")
    if scorer.identity != spec.evaluation:
        raise ValueError("Scorer identity differs from the admitted ExperimentSpec")
    if seed not in spec.seeds:
        raise ValueError("Trial seed is outside the admitted ExperimentSpec")
    if opponent_policy not in spec.opponent_policies:
        raise ValueError("opponent policy is outside the admitted ExperimentSpec")

    manifest = build_trial_manifest(
        spec=spec,
        actor=actor.identity,
        world=world.identity,
        evaluation=scorer.identity,
        seed=seed,
        opponent_policy=opponent_policy,
    )
    staging, final = prepare_trial_staging(output_dir, manifest)
    try:
        recorder = TraceRecorder(staging / "trace.jsonl")
        world.reset(
            trial_id=manifest.trial_id,
            seed=seed,
            opponent_policy=opponent_policy,
        )
        actor.reset(
            trial_id=manifest.trial_id,
            seed=seed,
            opponent_policy=opponent_policy,
        )

        turn = 0
        while turn < spec.max_turns and not world.done():
            observation = world.observe(actor.identity.actor_id)
            decision = actor.decide(observation)
            effect = world.step(actor.identity.actor_id, decision)
            actor.update(observation, decision, effect)
            recorder.append(
                TraceEvent(
                    event_id=f"{manifest.trial_id}:event-{turn + 1}",
                    trial_id=manifest.trial_id,
                    turn=observation.turn,
                    actor_id=actor.identity.actor_id,
                    observation=observation,
                    decision=decision,
                    effect=effect,
                    world_truth_digest=digest_json(world.truth()),
                )
            )
            turn += 1

        if not recorder.verify():
            raise RuntimeError(
                f"trace verification failed for {manifest.trial_id}"
            )

        hidden = HiddenEvaluationRecord.create(
            trial_id=manifest.trial_id,
            world_identity=world.identity,
            payload=world.evaluation_record(),
        )
        actor_usage = dict(actor.usage())
        outcome = scorer.score(hidden.payload, actor_usage=actor_usage)
        result = TrialResult(
            trial_id=manifest.trial_id,
            trial_key=manifest.trial_key,
            experiment_id=spec.experiment_id,
            seed=seed,
            opponent_policy=opponent_policy,
            actor_identity=actor.identity,
            world_identity=world.identity,
            evaluation_identity=scorer.identity,
            manifest_digest=digest_json(manifest.to_dict()),
            hidden_evaluation_digest=hidden.payload_digest,
            trace_digest=recorder.digest(),
            event_count=recorder.count,
            outcome=outcome,
            metadata={
                "world": dict(world.metadata()),
                "actor_usage": actor_usage,
                "spec_digest": digest_json(spec.to_dict()),
            },
        )
        write_json(
            staging / "hidden-evaluation-record.json",
            hidden.to_dict(),
        )
        write_json(staging / "result.json", result.to_dict())
        seal_and_commit_trial(staging, final, manifest)
        return result
    except BaseException:
        discard_trial_staging(staging)
        raise


def run_family(
    *,
    spec: ExperimentSpec,
    world_factory: Callable[[], WorldAdapter],
    actor_factory: Callable[[], Actor],
    scorer_factory: Callable[[], Scorer],
    output_dir: Path,
) -> FamilySummary:
    output_dir.mkdir(parents=True, exist_ok=True)
    spec_path = output_dir / "experiment-spec.json"
    if spec_path.exists():
        retained = ExperimentSpec.from_path(spec_path)
        if retained != spec:
            raise ValueError(
                "experiment output is bound to a different ExperimentSpec"
            )
    else:
        write_json(spec_path, spec.to_dict())

    results: list[TrialResult] = []
    for opponent_policy in spec.opponent_policies:
        for seed in spec.seeds:
            results.append(
                run_trial(
                    spec=spec,
                    world=world_factory(),
                    actor=actor_factory(),
                    scorer=scorer_factory(),
                    seed=seed,
                    opponent_policy=opponent_policy,
                    output_dir=output_dir,
                )
            )

    groups = _aggregate(results)
    summary = FamilySummary(
        experiment_id=spec.experiment_id,
        trial_count=len(results),
        groups=groups,
        trial_result_digests=tuple(
            digest_json(result.to_dict()) for result in results
        ),
    )
    write_json(output_dir / "summary.json", summary.to_dict())
    write_json(
        output_dir / "trial-index.json",
        [result.to_dict() for result in results],
    )
    return summary


def _aggregate(results: Iterable[TrialResult]) -> dict[str, Mapping[str, Any]]:
    materialized = list(results)
    grouped: dict[str, list[TrialResult]] = {}
    for result in materialized:
        grouped.setdefault(result.opponent_policy, []).append(result)
    grouped["__all__"] = materialized

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
