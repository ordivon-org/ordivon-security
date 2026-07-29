#!/usr/bin/env python3
"""Build the sanitized Round 1 evidence summary from ignored raw artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "round1"
OUTPUT = ROOT / "evidence" / "experiments" / "round1-20260730.json"
MODEL_FAMILIES = (
    "hermes-transcript",
    "hermes-strategic",
    "codex-transcript",
    "codex-strategic",
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text())


def source_base_revision() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def implementation_files() -> list[Path]:
    files = sorted((ROOT / "ordivon_security_experiments").glob("*.py"))
    files.extend(
        ROOT / relative
        for relative in (
            "scripts/analyze_adversarial_results.py",
            "scripts/bootstrap_cage4.sh",
            "scripts/build_round1_evidence.py",
            "scripts/codex_decision_provider.sh",
            "scripts/hermes_decision_provider.sh",
            "scripts/run_adversarial_experiment.py",
            "scripts/run_cage4_baseline.py",
            "scripts/run_round1_acceptance.sh",
            "schemas/decision.schema.json",
        )
    )
    return sorted(files)


def model_results() -> dict[str, Any]:
    output: dict[str, Any] = {}
    for name in MODEL_FAMILIES:
        family = ARTIFACTS / name
        trial_index = family / "trial-index.json"
        summary = family / "summary.json"
        result = load(trial_index)[0]
        output[name] = {
            "trial_count": 1,
            "seed": result["seed"],
            "opponent_policy": result["opponent_policy"],
            "outcome": result["outcome"],
            "actor_usage": result["metadata"]["actor_usage"],
            "trace_digest": result["trace_digest"],
            "trial_index_digest": digest(trial_index),
            "summary_digest": digest(summary),
        }
    return output


def main() -> int:
    micro_path = ARTIFACTS / "micro-comparison.json"
    cage_summary_path = ARTIFACTS / "cage4" / "summary.json"
    cage_index_path = ARTIFACTS / "cage4" / "trial-index.json"
    micro = load(micro_path)
    cage = load(cage_summary_path)
    models = model_results()
    implementation = implementation_files()
    implementation_manifest = "\n".join(
        f"{digest(path)}  {path.relative_to(ROOT).as_posix()}" for path in implementation
    ) + "\n"

    hermes_seconds = sum(
        float(models[name]["actor_usage"].get("provider_elapsed_seconds", 0.0))
        for name in ("hermes-transcript", "hermes-strategic")
    )
    codex_seconds = sum(
        float(models[name]["actor_usage"].get("provider_elapsed_seconds", 0.0))
        for name in ("codex-transcript", "codex-strategic")
    )
    codex_tokens = {
        name: int(models[name]["actor_usage"].get("provider_reported_tokens", 0))
        for name in ("codex-transcript", "codex-strategic")
    }

    payload = {
        "schema_version": 1,
        "evidence_id": "ORDIVON-SECURITY-ROUND1-20260730",
        "source_base_revision": source_base_revision(),
        "implementation_file_manifest_digest": "sha256:"
        + hashlib.sha256(implementation_manifest.encode()).hexdigest(),
        "implementation_files": [
            {"path": path.relative_to(ROOT).as_posix(), "digest": digest(path)}
            for path in implementation
        ],
        "scope": {
            "authority": "owned local deterministic simulation and pinned external CAGE 4 simulation only",
            "external_effects": "none",
            "claims": "experimental plumbing and initial comparative evidence; not a general capability ranking",
        },
        "micro_contest": {
            "trial_count": sum(int(value["trial_count"]) for value in micro.values()),
            "actor_family_count": len(micro),
            "opponent_policies": [
                "alpha-decoy-switch",
                "beta-decoy-switch",
                "adaptive-counter",
            ],
            "seeds": [1, 2, 3, 4, 5],
            "comparison_digest": digest(micro_path),
            "results": micro,
        },
        "cage4": {
            **cage,
            "summary_digest": digest(cage_summary_path),
            "trial_index_digest": digest(cage_index_path),
            "steps_per_trial": 60,
            "seeds": [1, 2, 3, 4, 5],
        },
        "model_ablations": {
            "trial_count": len(models),
            "warning": "one trial per provider/memory mode; diagnostic only",
            "results": models,
        },
        "execution_observations": {
            "hermes_provider_elapsed_seconds": round(hermes_seconds, 6),
            "codex_provider_elapsed_seconds": round(codex_seconds, 6),
            "decision_calls_per_model_trial": 6,
            "codex_provider_reported_tokens": codex_tokens,
            "warning": "provider-reported tokens and local elapsed time are not normalized provider benchmarks",
        },
        "decisions": [
            {
                "object": "ExperimentSpec, ActorIdentity, WorldIdentity, EvaluationIdentity, Observation, TrialResult, TrialOutcome",
                "decision": "retain inside Security experiment layer",
                "reason": "used across local and external-world experiments",
            },
            {
                "object": "explicit opponent hypotheses",
                "decision": "retain as research variable, not protocol",
                "reason": "improved local diagnostic information and switch recognition, but did not establish transferable capability",
            },
            {
                "object": "Campaign or strategic state",
                "decision": "do not promote",
                "reason": "all four one-seed model Trials failed the objective; explicit state changed trace structure and information outcome but did not improve success",
            },
            {
                "object": "multi-Agent organization ontology",
                "decision": "do not promote",
                "reason": "one synthetic compromised-member scenario is insufficient",
            },
            {
                "object": "command-backed stateless model provider",
                "decision": "retain only as baseline adapter",
                "reason": "works, but repeated session startup dominates cost and belongs in Host continuity work",
            },
            {
                "object": "custom cyber range",
                "decision": "reject",
                "reason": "pinned minimal CAGE 4 supplied authoritative state, partial observations, actors, phases, and repeated trials",
            },
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(f"evidence={OUTPUT.relative_to(ROOT)}")
    print(f"digest={digest(OUTPUT)}")
    print(
        "trials="
        + str(
            payload["micro_contest"]["trial_count"]
            + payload["cage4"]["trial_count"]
            + payload["model_ablations"]["trial_count"]
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
