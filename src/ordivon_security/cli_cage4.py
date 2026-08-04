from __future__ import annotations

import argparse
import json
from pathlib import Path

from ._canonical import canonical_digest
from .actors.scripted import SequenceActorBackend
from .contest.model import ActorBinding, ScenarioManifest
from .contest.runner import ContestRunner
from .ranges.cage4 import (
    CAGE4_NATIVE_PLAN,
    CAGE4_PLANS,
    CAGE4_RANGE_ID,
    CAGE4_REVISION,
    CAGE4_SLEEP_PLAN,
    Cage4RangeBackend,
    Cage4RangeConfig,
)


def _plan_digest(actions: tuple[str, ...]) -> str:
    return canonical_digest({"actions": list(actions)})


def build_cage4_manifest(
    config: Cage4RangeConfig,
    *,
    red_actions: tuple[str, ...],
    blue_actions: tuple[str, ...],
    steps: int,
) -> ScenarioManifest:
    return ScenarioManifest(
        scenario_id="scenario:cage4-enterprise-team-control",
        revision="1",
        range_id=CAGE4_RANGE_ID,
        actors=(
            ActorBinding(
                actor_id="actor:red",
                side="red",
                backend_id="backend:scripted-sequence-v1",
                backend_config_digest=_plan_digest(red_actions),
                objective="expand footholds and degrade defended enterprise services",
                allowed_actions=CAGE4_PLANS,
            ),
            ActorBinding(
                actor_id="actor:blue",
                side="blue",
                backend_id="backend:scripted-sequence-v1",
                backend_config_digest=_plan_digest(blue_actions),
                objective="preserve enterprise availability and constrain Red footholds",
                allowed_actions=CAGE4_PLANS,
            ),
        ),
        max_ticks=steps,
        metadata={
            "authorization": "owned-pinned-cage4-simulation",
            "cage4SourceRevision": CAGE4_REVISION,
            "cage4RangeConfigDigest": config.digest,
        },
    )


def _plan_sequence(plan: str, steps: int) -> tuple[str, ...]:
    action = CAGE4_NATIVE_PLAN if plan == "native" else CAGE4_SLEEP_PLAN
    return (action,) * steps


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run pinned CAGE 4 with Red and Blue actions explicitly controlled by Ordivon"
    )
    parser.add_argument("--source", type=Path, default=Path(".cache/cage4"))
    parser.add_argument("--output", type=Path, default=Path(".artifacts/security-cage4"))
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--steps", type=int, default=5)
    parser.add_argument("--red", choices=("native", "sleep"), default="native")
    parser.add_argument("--blue", choices=("native", "sleep"), default="native")
    args = parser.parse_args()
    if args.steps < 1:
        parser.error("--steps must be positive")

    config = Cage4RangeConfig(source_path=str(args.source))
    red_actions = _plan_sequence(args.red, args.steps)
    blue_actions = _plan_sequence(args.blue, args.steps)
    manifest = build_cage4_manifest(
        config,
        red_actions=red_actions,
        blue_actions=blue_actions,
        steps=args.steps,
    )
    runner = ContestRunner(
        Cage4RangeBackend(config),
        {
            "actor:red": SequenceActorBackend("actor:red", red_actions),
            "actor:blue": SequenceActorBackend("actor:blue", blue_actions),
        },
        evidence_root=args.output,
    )
    result = runner.run(manifest, seed=args.seed)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
