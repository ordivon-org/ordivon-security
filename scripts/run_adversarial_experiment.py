#!/usr/bin/env python3
"""Run the local dynamic-opponent Contest with one bounded actor family."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ordivon_security_experiments.actors import (  # noqa: E402
    CommandDecisionActor,
    CommitteeActor,
    GreedyActor,
    OpponentAwareActor,
)
from ordivon_security_experiments.micro_contest import MicroContestWorld  # noqa: E402
from ordivon_security_experiments.models import (  # noqa: E402
    ActorIdentity,
    EvaluationIdentity,
    ExperimentSpec,
)
from ordivon_security_experiments.runner import run_family  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--actor",
        required=True,
        choices=(
            "greedy",
            "opponent-aware",
            "committee-naive",
            "committee-compartmentalized",
            "committee-compromised-naive",
            "committee-compromised-compartmentalized",
            "hermes-transcript",
            "hermes-strategic",
            "codex-transcript",
            "codex-strategic",
        ),
    )
    parser.add_argument("--seeds", default="1,2,3,4,5")
    parser.add_argument(
        "--opponents",
        default="alpha-decoy-switch,beta-decoy-switch,adaptive-counter",
    )
    parser.add_argument("--max-turns", type=int, default=8)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def actor_factory(name: str):
    if name == "greedy":
        identity = ActorIdentity("greedy-red", "Red", "scripted", "GreedyActor")
        return lambda: GreedyActor(identity)
    if name == "opponent-aware":
        identity = ActorIdentity(
            "opponent-aware-red",
            "Red",
            "explicit-hypothesis",
            "OpponentAwareActor",
            memory_mode="structured-opponent-hypotheses",
        )
        return lambda: OpponentAwareActor(identity)
    if name.startswith("committee-"):
        compromised = "compromised" in name
        compartmentalized = "compartmentalized" in name
        identity = ActorIdentity(
            actor_id=name,
            role="Red organization",
            policy_type="multi-agent-organization",
            implementation="CommitteeActor",
            memory_mode="specialist-local-state",
            organization_id=name,
        )
        return lambda: CommitteeActor(
            identity,
            compartmentalized=compartmentalized,
            compromised_member=compromised,
        )
    provider, mode = name.split("-", 1)
    if provider == "hermes":
        command = (str(ROOT / "scripts" / "hermes_decision_provider.sh"), "{prompt}")
        model = "deepseek-v4-pro"
    else:
        command = (str(ROOT / "scripts" / "codex_decision_provider.sh"), "{prompt}")
        model = "codex-configured-model"
    identity = ActorIdentity(
        actor_id=name,
        role="Red",
        policy_type="llm-command-provider",
        implementation="CommandDecisionActor",
        model=model,
        scaffold_revision="bounded-json-decision-v1",
        memory_mode=mode,
        resource_budget={"decision_timeout_seconds": 120},
    )
    return lambda: CommandDecisionActor(identity, command=command, mode=mode, timeout_seconds=120)


def main() -> int:
    args = parse_args()
    seeds = tuple(int(value) for value in args.seeds.split(",") if value)
    opponents = tuple(value for value in args.opponents.split(",") if value)
    factory = actor_factory(args.actor)
    actor = factory()
    world = MicroContestWorld(max_turns=args.max_turns)
    spec = ExperimentSpec(
        experiment_id=f"EXP-002-{args.actor}",
        world=world.identity,
        actor=actor.identity,
        evaluation=EvaluationIdentity("micro-contest-multidimensional-judge", "1"),
        seeds=seeds,
        opponent_policies=opponents,
        max_turns=args.max_turns,
        metadata={
            "purpose": "dynamic-opponent strategic baseline and ablation",
            "external_effects": "none; deterministic local simulation",
        },
    )
    summary = run_family(
        spec=spec,
        world_factory=lambda: MicroContestWorld(max_turns=args.max_turns),
        actor_factory=factory,
        output_dir=args.output,
    )
    print(f"experiment={summary.experiment_id}")
    print(f"trials={summary.trial_count}")
    print(f"summary={args.output / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
