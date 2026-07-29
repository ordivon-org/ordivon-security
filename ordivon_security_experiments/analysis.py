"""Cross-family comparisons using only the standard library."""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import statistics
from typing import Any, Iterable, Mapping

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


def load_trial_index(path: Path) -> list[Mapping[str, Any]]:
    value = json.loads(path.read_text())
    if not isinstance(value, list):
        raise ValueError(f"{path} must contain a list")
    return value


def compare_actor_families(index_paths: Iterable[Path]) -> dict[str, Any]:
    by_actor: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for path in index_paths:
        for result in load_trial_index(path):
            actor = result["actor_identity"]["actor_id"]
            by_actor[str(actor)].append(result)

    output: dict[str, Any] = {}
    for actor, results in sorted(by_actor.items()):
        actor_summary: dict[str, Any] = {"trial_count": len(results)}
        for metric in _METRICS:
            values = [float(result["outcome"][metric]) for result in results]
            actor_summary[metric] = {
                "mean": statistics.fmean(values),
                "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
                "min": min(values),
                "max": max(values),
            }
        actor_summary["objective_rate"] = statistics.fmean(
            float(bool(result["outcome"]["details"].get("objective_achieved"))) for result in results
        )
        actor_summary["decoy_trigger_rate"] = statistics.fmean(
            float(bool(result["outcome"]["details"].get("decoy_triggered"))) for result in results
        )
        actor_summary["switch_recognition_rate"] = statistics.fmean(
            float(bool(result["outcome"]["details"].get("policy_switch_recognized"))) for result in results
        )
        output[actor] = actor_summary
    return output
