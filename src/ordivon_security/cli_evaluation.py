from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation import (
    AuthorityManifest,
    EnvironmentIdentity,
    EvaluationRunner,
    EvaluationSpec,
    FixtureEvaluationBackend,
    GuardianPolicy,
    ObservationPlan,
    SampleVault,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a local Evaluation Trial dry run without executing Sample bytes."
    )
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-index", type=int, default=0)
    parser.add_argument("--media-type", default="application/octet-stream")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    vault = SampleVault(args.vault)
    sample = vault.import_path(args.sample, media_type=args.media_type)
    guardian = GuardianPolicy(
        policy_id="guardian-policy:local-dry-run",
        revision="1",
        network_mode="deny-all",
        max_runtime_ms=1_000,
        max_memory_mib=128,
        max_processes=1,
        max_artifact_bytes=1_048_576,
        terminate_on=("unauthorized-network", "resource-limit", "operator-stop"),
    )
    observation = ObservationPlan(
        plan_id="observation-plan:local-dry-run",
        revision="1",
        channels=("sample", "management", "observer", "guardian", "world-truth"),
        capture_memory="never",
        max_event_bytes=65_536,
    )
    backend = FixtureEvaluationBackend()
    environment = EnvironmentIdentity(
        environment_id="environment:local-dry-run",
        provider_id=backend.provider_id,
        provider_revision="1",
        image_digest=canonical_digest({"fixtureImage": "none"}),
        configuration_digest=canonical_digest({"sampleExecution": False}),
        guardian_policy_digest=guardian.digest,
        observation_plan_digest=observation.digest,
    )
    authority = AuthorityManifest(
        authority_id="authority:local-operator-dry-run",
        revision="1",
        sample_digest=sample.sha256,
        operator_id="operator:local",
        authorization_basis=(
            "Local contract and evidence validation only; Sample bytes are not executed."
        ),
        permitted_environment_ids=(environment.environment_id,),
        permitted_actions=("observe-only",),
        prohibited_actions=("execute-sample", "network-access"),
        max_runtime_ms=1_000,
        allow_network=False,
    )
    spec = EvaluationSpec(
        evaluation_id="evaluation:local-dry-run",
        revision="1",
        sample=sample,
        authority=authority,
        environment=environment,
        guardian_policy=guardian,
        observation_plan=observation,
        requested_actions=("observe-only",),
        metadata={"sampleExecution": False},
    )
    result = EvaluationRunner(backend, vault, evidence_root=args.output).run(
        spec,
        run_index=args.run_index,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
