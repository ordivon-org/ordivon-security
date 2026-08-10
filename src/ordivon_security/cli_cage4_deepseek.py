from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

from .actors.agent_stack import (
    AgentLayerBinding,
    AgentTurnDriver,
    DeepSeekHarnessTurnDriver,
    HarnessBudgetConfig,
)
from .actors.native_harness import NativeHarnessActorBackend
from .contest.model import ActorBinding, ScenarioManifest
from .contest.runner import ContestRunner
from .integrations import (
    HostAssignedDeepSeekHarnessTurnDriver,
    RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver,
)
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


def _prepare_private_state_root(path: Path, label: str) -> Path:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"{label} must be a private directory")
        if any(path.iterdir()):
            raise ValueError(f"{label} must be empty for a new Trial")
    else:
        path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    return path.resolve()


def _paths_overlap(first: Path, second: Path) -> bool:
    first_resolved = first.resolve()
    second_resolved = second.resolve()
    return (
        first_resolved == second_resolved
        or first_resolved.is_relative_to(second_resolved)
        or second_resolved.is_relative_to(first_resolved)
    )


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
    variant: str,
    host_state_root: Path | None,
    host_state_namespace: str | None,
    host_context_token_budget: int,
    runtime_endpoint: str,
    runtime_token_file: Path,
    runtime_request_root: Path | None,
    security_source_repo: Path,
    security_source_revision: str,
    harness_source: Path,
    host_source: Path,
    protocol_source: Path,
    python_executable: Path,
    runtime_timeout_ms: int,
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
            "experimentalVariant": (
                "security-host-runtime-harness-provider"
                if variant == "p0c"
                else (
                    "security-host-harness-provider"
                    if variant == "p0b"
                    else "security-harness-provider"
                )
            ),
        },
    )
    baseline = DeepSeekHarnessTurnDriver(
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
    driver: AgentTurnDriver = baseline
    if variant in {"p0b", "p0c"}:
        if host_state_root is None or host_state_namespace is None:
            raise ValueError("Host-backed variants require Host state root and namespace")
        if variant == "p0b":
            driver = HostAssignedDeepSeekHarnessTurnDriver(
                delegate=baseline,
                host_state_root=host_state_root / side,
                host_state_namespace=f"{host_state_namespace}:{side}",
                host_source_revision=host_revision,
                context_token_budget=host_context_token_budget,
            )
        else:
            if runtime_request_root is None:
                raise ValueError("P0-C requires a private Runtime request root")
            driver = RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver(
                delegate=baseline,
                host_state_root=host_state_root / side,
                host_state_namespace=f"{host_state_namespace}:{side}",
                host_source_revision=host_revision,
                runtime_source_revision=runtime_revision,
                runtime_endpoint=runtime_endpoint,
                runtime_token_file=runtime_token_file,
                runtime_request_root=runtime_request_root / side,
                security_source_repo=security_source_repo,
                security_source_revision=security_source_revision,
                harness_source=harness_source,
                host_source=host_source,
                protocol_source=protocol_source,
                python_executable=python_executable,
                context_token_budget=host_context_token_budget,
                runtime_timeout_ms=runtime_timeout_ms,
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
    variant: str,
) -> ScenarioManifest:
    host_consumed = variant in {"p0b", "p0c"}
    runtime_consumed = variant == "p0c"
    experiment_variant = (
        "security-host-runtime-harness-provider"
        if runtime_consumed
        else ("security-host-harness-provider" if host_consumed else "security-harness-provider")
    )
    return ScenarioManifest(
        scenario_id=f"scenario:cage4-deepseek-harness-{variant}",
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
            "agentExperimentVariant": experiment_variant,
            "hostConsumed": host_consumed,
            "runtimeConsumed": runtime_consumed,
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run pinned CAGE 4 with Red and Blue DeepSeek Flash Actors through the "
            "Ordivon Harness domain loop."
        )
    )
    parser.add_argument(
        "--variant",
        choices=("p0a", "p0b", "p0c"),
        default="p0a",
        help=(
            "P0-A uses Harness directly; P0-B adds Host; P0-C executes each "
            "Host Assignment through Runtime."
        ),
    )
    parser.add_argument("--source", type=Path, default=Path(".cache/cage4"))
    parser.add_argument("--output", type=Path)
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
        "--host-state-root",
        type=Path,
        help="Private Host state parent used by P0-B and P0-C.",
    )
    parser.add_argument(
        "--host-state-namespace",
        help="Non-secret Host state namespace identity; must start with host-state:.",
    )
    parser.add_argument("--host-context-tokens", type=int, default=12_000)
    parser.add_argument(
        "--security-source",
        type=Path,
        default=Path("."),
        help="Clean Security Git source used to open the P0-C Runtime Workspace.",
    )
    parser.add_argument(
        "--runtime-endpoint",
        default="http://127.0.0.1:8897/mcp",
    )
    parser.add_argument(
        "--runtime-token-file",
        type=Path,
        default=Path("/etc/ordivon/ordivon-runtime.env"),
    )
    parser.add_argument(
        "--runtime-request-root",
        type=Path,
        help="Fresh private request spool used only by P0-C.",
    )
    parser.add_argument("--runtime-timeout-ms", type=int, default=300_000)
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
    parser.add_argument(
        "--total-tokens",
        type=int,
        default=1_000_000,
        help=(
            "Run-wide token safety ceiling. This is a runaway guard, not a cost target; "
            "model-call, wall-time, tool-call, and output bounds remain primary."
        ),
    )
    parser.add_argument("--max-output-tokens", type=int, default=1_024)
    parser.add_argument("--model-observation-bytes", type=int, default=262_144)
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Retain an incomplete or actor-failed Trial without returning exit status 2.",
    )
    parser.add_argument("--provider-timeout-seconds", type=float, default=90.0)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    output = args.output or Path(f".artifacts/cage4-deepseek-{args.variant}")
    if args.steps < 1:
        parser.error("--steps must be positive")
    if args.red_secret.resolve() == args.blue_secret.resolve():
        parser.error("Red and Blue must use distinct credential files")
    if args.host_context_tokens < 1:
        parser.error("--host-context-tokens must be positive")
    if args.variant in {"p0b", "p0c"}:
        if args.host_state_root is None or args.host_state_namespace is None:
            parser.error(
                "Host-backed variants require --host-state-root and --host-state-namespace"
            )
        if not args.host_state_root.is_absolute():
            parser.error("--host-state-root must be absolute")
        if not args.host_state_namespace.startswith("host-state:"):
            parser.error("--host-state-namespace must start with host-state:")
    elif args.host_state_root is not None or args.host_state_namespace is not None:
        parser.error("Host state options are valid only with --variant p0b or p0c")
    if args.variant == "p0c":
        if args.runtime_request_root is None or not args.runtime_request_root.is_absolute():
            parser.error("P0-C requires absolute --runtime-request-root")
        if args.runtime_timeout_ms < 1:
            parser.error("--runtime-timeout-ms must be positive")
    elif args.runtime_request_root is not None:
        parser.error("--runtime-request-root is valid only with --variant p0c")

    security_revision = _git_revision(args.security_source, "Security")
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
    host_state_root = args.host_state_root
    if args.variant in {"p0b", "p0c"}:
        assert host_state_root is not None
        try:
            host_state_root = _prepare_private_state_root(host_state_root, "Host state root")
        except ValueError as error:
            parser.error(str(error))
        if _paths_overlap(output, host_state_root):
            parser.error("Contest evidence output and Host state root must be disjoint")
    runtime_request_root = args.runtime_request_root
    if args.variant == "p0c":
        assert runtime_request_root is not None
        try:
            runtime_request_root = _prepare_private_state_root(
                runtime_request_root, "Runtime request root"
            )
        except ValueError as error:
            parser.error(str(error))
        assert host_state_root is not None
        if _paths_overlap(output, runtime_request_root):
            parser.error("Contest evidence output and Runtime request root must be disjoint")
        if _paths_overlap(host_state_root, runtime_request_root):
            parser.error("Host state root and Runtime request root must be disjoint")
    budget = HarnessBudgetConfig(
        max_model_calls=args.model_calls,
        max_tool_calls=3,
        max_observation_bytes=131_072,
        max_wall_time_ms=args.wall_time_ms,
        max_total_tokens=args.total_tokens,
        max_model_retries=args.model_retries,
        max_tool_corrections=1,
        max_observation_only_turns=1,
        max_no_progress_turns=2,
        max_model_observation_bytes=args.model_observation_bytes,
    )
    common = {
        "harness_revision": harness_revision,
        "harness_version": harness_version,
        "protocol_revision": protocol_revision,
        "host_revision": host_revision,
        "runtime_revision": runtime_revision,
        "budget": budget,
        "timeout_seconds": args.provider_timeout_seconds,
        "max_output_tokens": args.max_output_tokens,
        "variant": args.variant,
        "host_state_root": host_state_root,
        "host_state_namespace": args.host_state_namespace,
        "host_context_token_budget": args.host_context_tokens,
        "runtime_endpoint": args.runtime_endpoint,
        "runtime_token_file": args.runtime_token_file,
        "runtime_request_root": runtime_request_root,
        "security_source_repo": args.security_source.resolve(),
        "security_source_revision": security_revision,
        "harness_source": args.harness_source.resolve(),
        "host_source": args.host_source.resolve(),
        "protocol_source": args.protocol_source.resolve(),
        "python_executable": Path(sys.executable).resolve(),
        "runtime_timeout_ms": args.runtime_timeout_ms,
    }
    red = _build_actor(
        actor_id="actor:red",
        side="red",
        objective="expand footholds and degrade defended enterprise services",
        secret_path=args.red_secret,
        **common,
    )
    blue = _build_actor(
        actor_id="actor:blue",
        side="blue",
        objective="preserve enterprise availability and constrain Red footholds",
        secret_path=args.blue_secret,
        **common,
    )
    if red.driver.credential_scope_id == blue.driver.credential_scope_id:
        parser.error("Red and Blue credentialScopeId values must differ")

    config = Cage4RangeConfig(source_path=str(args.source))
    manifest = _manifest(
        config,
        red=red,
        blue=blue,
        steps=args.steps,
        variant=args.variant,
    )
    result = ContestRunner(
        Cage4RangeBackend(config),
        {"actor:red": red, "actor:blue": blue},
        evidence_root=output,
    ).run(manifest, seed=args.seed)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    if result.ticks_executed != args.steps and not args.allow_incomplete:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
