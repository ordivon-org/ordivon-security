from __future__ import annotations

import argparse
import json
from pathlib import Path

from ._canonical import canonical_digest
from .actors.scripted import SequenceActorBackend
from .contest.model import ActorBinding, ScenarioManifest
from .contest.runner import ContestRunner
from .ranges.micro import MicroContestRange

_RED_ACTIONS = ("recon", "exploit_web", "pivot_vault", "exfiltrate", "wait")
_REACTIVE_BLUE_ACTIONS = ("wait", "monitor", "isolate_vault", "wait", "wait")
_SLEEPY_BLUE_ACTIONS = ("wait", "wait", "wait", "wait", "wait")


def _sequence_digest(actions: tuple[str, ...]) -> str:
    return canonical_digest({"actions": list(actions)})


def build_manifest(
    *,
    red_actions: tuple[str, ...] = _RED_ACTIONS,
    blue_actions: tuple[str, ...] = _REACTIVE_BLUE_ACTIONS,
) -> ScenarioManifest:
    return ScenarioManifest(
        scenario_id="scenario:micro-red-blue",
        revision="1",
        range_id=MicroContestRange.range_id,
        actors=(
            ActorBinding(
                actor_id="actor:red",
                side="red",
                backend_id="backend:scripted-sequence-v1",
                backend_config_digest=_sequence_digest(red_actions),
                objective="exfiltrate protected data",
                allowed_actions=("recon", "exploit_web", "pivot_vault", "exfiltrate", "wait"),
            ),
            ActorBinding(
                actor_id="actor:blue",
                side="blue",
                backend_id="backend:scripted-sequence-v1",
                backend_config_digest=_sequence_digest(blue_actions),
                objective="preserve protected data and service availability",
                allowed_actions=("monitor", "patch_web", "isolate_vault", "deploy_decoy", "wait"),
            ),
        ),
        max_ticks=5,
        metadata={"authorization": "owned-synthetic-range"},
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the deterministic Ordivon Security micro Contest"
    )
    parser.add_argument("--output", type=Path, default=Path(".artifacts/security-micro"))
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--blue", choices=("sleepy", "reactive"), default="reactive")
    args = parser.parse_args()
    blue_actions = _SLEEPY_BLUE_ACTIONS if args.blue == "sleepy" else _REACTIVE_BLUE_ACTIONS
    manifest = build_manifest(blue_actions=blue_actions)
    runner = ContestRunner(
        MicroContestRange(),
        {
            "actor:red": SequenceActorBackend("actor:red", _RED_ACTIONS),
            "actor:blue": SequenceActorBackend("actor:blue", blue_actions),
        },
        evidence_root=args.output,
    )
    result = runner.run(manifest, seed=args.seed)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
