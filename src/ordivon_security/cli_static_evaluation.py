from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation import (
    ArchiveInventoryAnalyzer,
    AuthenticodeReportAnalyzer,
    AuthorityManifest,
    ClamAvAnalyzer,
    ClamAvReportAnalyzer,
    EnvironmentIdentity,
    EvaluationRunner,
    EvaluationSpec,
    FileIdentityAnalyzer,
    GuardianPolicy,
    ImportedReportAnalyzer,
    LocalStaticEvaluationBackend,
    ObservationPlan,
    SampleVault,
    StaticAnalyzer,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run an authorized local static Evaluation without loading or invoking Sample bytes."
        )
    )
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--run-index", type=int, default=0)
    parser.add_argument("--media-type", default="application/octet-stream")
    parser.add_argument(
        "--authorization-basis",
        required=True,
        help="Operator-supplied basis establishing authority to analyze this exact local Sample.",
    )
    parser.add_argument("--max-sample-bytes", type=int)
    parser.add_argument("--max-vault-bytes", type=int)
    parser.add_argument("--max-artifact-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument(
        "--archive-inventory",
        action="store_true",
        help="Use 7-Zip listing mode. Archive contents are not extracted or executed.",
    )
    parser.add_argument(
        "--clamav",
        action="store_true",
        help="Run ClamAV against the exact Vault object. This may be slow for large files.",
    )
    parser.add_argument(
        "--clamav-report",
        type=Path,
        help="Import and parse an existing ClamAV report as historical Observer evidence.",
    )
    parser.add_argument(
        "--authenticode-report",
        type=Path,
        help=(
            "Import a custom Authenticode digest-consistency summary. It is not treated as "
            "WinVerifyTrust evidence."
        ),
    )
    parser.add_argument(
        "--report",
        type=Path,
        action="append",
        default=[],
        help="Import another native report by digest without interpreting it. Repeatable.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    vault = SampleVault(
        args.vault,
        max_sample_bytes=args.max_sample_bytes,
        max_vault_bytes=args.max_vault_bytes,
    )
    sample = vault.import_path(args.sample, media_type=args.media_type)

    analyzers: list[StaticAnalyzer] = [FileIdentityAnalyzer()]
    if args.archive_inventory:
        analyzers.append(ArchiveInventoryAnalyzer())
    if args.clamav:
        analyzers.append(ClamAvAnalyzer())
    if args.clamav_report is not None:
        analyzers.append(ClamAvReportAnalyzer(args.clamav_report))
    if args.authenticode_report is not None:
        analyzers.append(AuthenticodeReportAnalyzer(args.authenticode_report))
    seen_report_ids: set[str] = set()
    for report_path in args.report:
        report_id = report_path.stem.replace(" ", "-").lower()
        if report_id in seen_report_ids:
            raise ValueError(f"Imported report identity is duplicated: {report_id}")
        seen_report_ids.add(report_id)
        analyzers.append(
            ImportedReportAnalyzer(
                report_id=report_id,
                tool_id="tool:operator-native-report",
                report_path=report_path,
                report_kind="native-static-report",
                limitations=(
                    "Imported report is retained by digest and is not automatically interpreted.",
                ),
            )
        )

    work_root = args.work_root or args.output.parent / "static-work"
    backend = LocalStaticEvaluationBackend(tuple(analyzers), work_root=work_root)
    guardian = GuardianPolicy(
        policy_id="guardian-policy:local-static-evaluation",
        revision="1",
        network_mode="deny-all",
        max_runtime_ms=30 * 60 * 1_000,
        max_memory_mib=2_048,
        max_processes=16,
        max_artifact_bytes=args.max_artifact_bytes,
        terminate_on=("network-attempt", "resource-limit", "operator-stop"),
    )
    observation = ObservationPlan(
        plan_id="observation-plan:local-static-evaluation",
        revision="1",
        channels=("sample", "management", "observer", "guardian", "world-truth"),
        capture_memory="never",
        max_event_bytes=256 * 1024,
    )
    environment = EnvironmentIdentity(
        environment_id="environment:local-static-evaluation",
        provider_id=backend.provider_id,
        provider_revision="1",
        image_digest=canonical_digest({"image": "none", "analysisMode": "static-only"}),
        configuration_digest=canonical_digest(backend.execution_identity),
        guardian_policy_digest=guardian.digest,
        observation_plan_digest=observation.digest,
    )
    authority = AuthorityManifest(
        authority_id="authority:local-static-operator",
        revision="1",
        sample_digest=sample.sha256,
        operator_id="operator:local",
        authorization_basis=args.authorization_basis,
        permitted_environment_ids=(environment.environment_id,),
        permitted_actions=("static-analyze",),
        prohibited_actions=("execute-sample", "network-access", "install-sample"),
        max_runtime_ms=guardian.max_runtime_ms,
        allow_network=False,
    )
    spec = EvaluationSpec(
        evaluation_id="evaluation:local-static",
        revision="1",
        sample=sample,
        authority=authority,
        environment=environment,
        guardian_policy=guardian,
        observation_plan=observation,
        requested_actions=("static-analyze",),
        metadata={
            "analysisMode": "static-only",
            "sampleExecution": False,
            "historicalReportsImported": bool(
                args.clamav_report or args.authenticode_report or args.report
            ),
        },
    )
    result = EvaluationRunner(backend, vault, evidence_root=args.output).run(
        spec,
        run_index=args.run_index,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
