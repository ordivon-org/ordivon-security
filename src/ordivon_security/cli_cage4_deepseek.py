from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

from .actors.agent_stack import (
    AgentLayerBinding,
    DeepSeekHarnessTurnDriver,
    HarnessBudgetConfig,
)
from .actors.native_harness import NativeHarnessActorBackend
from .contest.model import ActorBinding, ScenarioManifest
from .contest.runner import ContestRunner
from .ranges.cage4 import (
    CAGE4_PLANS,
    CAGE4_RANGE_ID,
    CAGE4_REVISION,
    Cage4RangeBackend,
    Cage4RangeConfig,
)


def _git_revision(path: Path, label: str) -> str:
    if not path.is_dir() or not (path / ".git").exists():
        raise ValueError(f"{label} source is not a Git repository: {path}")
    revision = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
    ).stdout.strip()
    if dirty:
        raise ValueError(f"{label} source tree must be clean")
    return revision


def _project_version(path: Path, label: str) -> str:
    pyproject = path / "pyproject.toml"
    if not pyproject.is_file():
        raise ValueError(f"{label} pyproject is missing: {pyproject}")
    value = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = value.get("project")
    if not isinstance(project, dict):
        raise ValueError(f"{label} pyproject lacks project metadata")
    version = project.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"{label} project version is invalid")
    return version


def _insert_agent_sources(
    *,
    harness_source: Path,
    host_source: Path,
    protocol_source: Path,
) -> None:
    candidates = (
        protocol_source / "src",
        host_source / "src",
        harness_source / "src",
    )
    for path in candidates:
        if not path.is_dir():
            raise ValueError(f"Agent source package root is missing: {path}")
    for path in candidates:
        text = str(path.resolve())
        if text not in sys.path:
            sys.path.insert(0, text)


def _build_actor(
    *,
    actor_id: str,
    side: str,
    objective: str,
    secret_path: Path,
    harness_revision: str,
    harness_version: str,
    protocol_revision: str,
    host_revision: str,
    runtime_revision: str,
    budget: HarnessBudgetConfig,
    timeout_seconds: float,
    max_output_tokens: int,
) -> NativeHarnessActorBackend:
    host_binding = AgentLayerBinding(
        component_id="ordivon-host",
        revision=host_revision,
        mode="not-consumed-security-domain-session",
        consumed=False,
        configuration={
            "reason": (
                "Security Contest owns Actor lifecycle and action admission in P0-A; "
                "no durable Host Task or Assignment is created."
            ),
            "experimentalVariant": "security-harness-provider",
        },
    )
    runtime_binding = AgentLayerBinding(
        component_id="ordivon-runtime",
        revision=runtime_revision,
        mode="not-consumed-domain-action",
        consumed=False,
        configuration={
            "reason": (
                "CAGE team-plan selection creates a Security ActionProposal and no "
                "physical Runtime effect."
            ),
            "experimentalVariant": "security-harness-provider",
        },
    )
    driver = DeepSeekHarnessTurnDriver(
        secret_path=secret_path,
        harness_source_revision=harness_revision,
        harness_declared_version=harness_version,
        harness_protocol_revision=protocol_revision,
        host_binding=host_binding,
        runtime_binding=runtime_binding,
        budget=budget,
        timeout_seconds=timeout_seconds,
        max_output_tokens=max_output_tokens,
    )
    return NativeHarnessActorBackend(
        actor_id=actor_id,
        side=side,
        objective=objective,
        driver=driver,
    )


def _manifest(
    config: Cage4RangeConfig,
    *,
    red: NativeHarnessActorBackend,
    blue: NativeHarnessActorBackend,
    steps: int,
) -> ScenarioManifest:
    return ScenarioManifest(
        scenario_id="scenario:cage4-deepseek-harness-p0a",
        revision="1",
        range_id=CAGE4_RANGE_ID,
        actors=(
            ActorBinding(
                actor_id=red.actor_id,
                side=red.side,
                backend_id=red.backend_id,
                backend_config_digest=red.configuration_digest,
                objective=red.objective,
                allowed_actions=CAGE4_PLANS,
            ),
            ActorBinding(
                actor_id=blue.actor_id,
                side=blue.side,
                backend_id=blue.backend_id,
                backend_config_digest=blue.configuration_digest,
                objective=blue.objective,
                allowed_actions=CAGE4_PLANS,
            ),
        ),
        max_ticks=steps,
        metadata={
            "authorization": "owned-pinned-cage4-simulation",
            "cage4SourceRevision": CAGE4_REVISION,
            "cage4RangeConfigDigest": config.digest,
            "agentExperimentVariant": "security-harness-provider",
            "hostConsumed": False,
            "runtimeConsumed": False,
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run pinned CAGE 4 with Red and Blue DeepSeek Flash Actors through the "
            "Ordivon Harness domain loop."
        )
    )
    parser.add_argument("--source", type=Path, default=Path(".cache/cage4"))
    parser.add_argument("--output", type=Path, default=Path(".artifacts/cage4-deepseek-p0a"))
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--steps", type=int, default=1)
    parser.add_argument("--red-secret", type=Path, required=True)
    parser.add_argument("--blue-secret", type=Path, required=True)
    parser.add_argument(
        "--harness-source",
        type=Path,
        default=Path("/root/projects/ordivon-harness"),
    )
    parser.add_argument(
        "--host-source",
        type=Path,
        default=Path("/root/projects/ordivon-host"),
    )
    parser.add_argument(
        "--runtime-source",
        type=Path,
        default=Path("/root/projects/ordivon-runtime"),
    )
    parser.add_argument(
        "--protocol-source",
        type=Path,
        default=Path("/root/projects/ordivon-computing/packages/ordivon-protocol"),
    )
    parser.add_argument(
        "--protocol-repository",
        type=Path,
        default=Path("/root/projects/ordivon-computing"),
    )
    parser.add_argument("--model-calls", type=int, default=3)
    parser.add_argument("--model-retries", type=int, default=1)
    parser.add_argument("--wall-time-ms", type=int, default=180_000)
    parser.add_argument("--total-tokens", type=int, default=16_384)
    parser.add_argument("--max-output-tokens", type=int, default=4_096)
    parser.add_argument("--provider-timeout-seconds", type=float, default=90.0)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.steps < 1:
        parser.error("--steps must be positive")
    if args.red_secret.resolve() == args.blue_secret.resolve():
        parser.error("Red and Blue must use distinct credential files in P0-A")

    harness_revision = _git_revision(args.harness_source, "Harness")
    host_revision = _git_revision(args.host_source, "Host")
    runtime_revision = _git_revision(args.runtime_source, "Runtime")
    protocol_revision = _git_revision(args.protocol_repository, "Computing protocol")
    harness_version = _project_version(args.harness_source, "Harness")
    _insert_agent_sources(
        harness_source=args.harness_source,
        host_source=args.host_source,
        protocol_source=args.protocol_source,
    )
    budget = HarnessBudgetConfig(
        max_model_calls=args.model_calls,
        max_tool_calls=1,
        max_observation_bytes=131_072,
        max_wall_time_ms=args.wall_time_ms,
        max_total_tokens=args.total_tokens,
        max_model_retries=args.model_retries,
        max_tool_corrections=1,
        max_observation_only_turns=1,
        max_no_progress_turns=1,
        max_model_observation_bytes=65_536,
    )
    red = _build_actor(
        actor_id="actor:red",
        side="red",
        objective="expand footholds and degrade defended enterprise services",
        secret_path=args.red_secret,
        harness_revision=harness_revision,
        harness_version=harness_version,
        protocol_revision=protocol_revision,
        host_revision=host_revision,
        runtime_revision=runtime_revision,
        budget=budget,
        timeout_seconds=args.provider_timeout_seconds,
        max_output_tokens=args.max_output_tokens,
    )
    blue = _build_actor(
        actor_id="actor:blue",
        side="blue",
        objective="preserve enterprise availability and constrain Red footholds",
        secret_path=args.blue_secret,
        harness_revision=harness_revision,
        harness_version=harness_version,
        protocol_revision=protocol_revision,
        host_revision=host_revision,
        runtime_revision=runtime_revision,
        budget=budget,
        timeout_seconds=args.provider_timeout_seconds,
        max_output_tokens=args.max_output_tokens,
    )
    if red.driver.credential_scope_id == blue.driver.credential_scope_id:
        parser.error("Red and Blue credentialScopeId values must differ")

    config = Cage4RangeConfig(source_path=str(args.source))
    manifest = _manifest(config, red=red, blue=blue, steps=args.steps)
    result = ContestRunner(
        Cage4RangeBackend(config),
        {"actor:red": red, "actor:blue": blue},
        evidence_root=args.output,
    ).run(manifest, seed=args.seed)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
