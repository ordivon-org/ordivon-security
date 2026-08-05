from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation import (
    ArchiveInventoryAnalyzer,
    AuthenticodeReportAnalyzer,
    AuthorityManifest,
    ClamAvReportAnalyzer,
    EnvironmentIdentity,
    EvaluationDisposition,
    EvaluationRunner,
    EvaluationSpec,
    FileIdentityAnalyzer,
    GuardianPolicy,
    ImportedReportAnalyzer,
    LocalStaticEvaluationBackend,
    ObservationPlan,
    SampleVault,
    harden_quarantine_tree,
    verify_evaluation_evidence,
    verify_evaluation_operational_evidence,
)


class StaticEvaluationP0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.vault = SampleVault(self.root / "vault", chunk_bytes=17)
        self.sample_source = self.root / "fixture.bin"
        self.sample_bytes = b"STATIC_FIXTURE_NOT_EXECUTED\x00" * 257
        self.sample_source.write_bytes(self.sample_bytes)
        self.sample = self.vault.import_path(self.sample_source)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _spec(
        self,
        backend: LocalStaticEvaluationBackend,
        *,
        max_artifact_bytes: int = 1_048_576,
    ) -> EvaluationSpec:
        guardian = GuardianPolicy(
            policy_id="guardian-policy:static-test",
            revision="1",
            network_mode="deny-all",
            max_runtime_ms=60_000,
            max_memory_mib=256,
            max_processes=8,
            max_artifact_bytes=max_artifact_bytes,
            terminate_on=("network-attempt", "resource-limit", "operator-stop"),
        )
        observation = ObservationPlan(
            plan_id="observation-plan:static-test",
            revision="1",
            channels=("sample", "management", "observer", "guardian", "world-truth"),
            capture_memory="never",
            max_event_bytes=256 * 1024,
        )
        environment = EnvironmentIdentity(
            environment_id="environment:static-test",
            provider_id=backend.provider_id,
            provider_revision="1",
            image_digest=canonical_digest({"image": "none"}),
            configuration_digest=canonical_digest(backend.execution_identity),
            guardian_policy_digest=guardian.digest,
            observation_plan_digest=observation.digest,
        )
        authority = AuthorityManifest(
            authority_id="authority:static-test",
            revision="1",
            sample_digest=self.sample.sha256,
            operator_id="operator:test",
            authorization_basis="Owned static fixture. Sample execution is prohibited.",
            permitted_environment_ids=(environment.environment_id,),
            permitted_actions=("static-analyze",),
            prohibited_actions=("execute-sample", "network-access"),
            max_runtime_ms=guardian.max_runtime_ms,
            allow_network=False,
        )
        return EvaluationSpec(
            evaluation_id="evaluation:static-test",
            revision="1",
            sample=self.sample,
            authority=authority,
            environment=environment,
            guardian_policy=guardian,
            observation_plan=observation,
            requested_actions=("static-analyze",),
            metadata={"sampleExecution": False, "analysisMode": "static-only"},
        )

    def _run(
        self,
        backend: LocalStaticEvaluationBackend,
        *,
        max_artifact_bytes: int = 1_048_576,
        run_index: int = 0,
    ):
        runner = EvaluationRunner(
            backend,
            self.vault,
            evidence_root=self.root / "evidence",
        )
        return runner.run(
            self._spec(backend, max_artifact_bytes=max_artifact_bytes),
            run_index=run_index,
        )

    def test_vault_streams_path_import_and_enforces_limits(self) -> None:
        resolved = self.vault.resolve(self.sample)
        self.assertEqual(resolved.read_bytes(), self.sample_bytes)
        self.assertEqual(stat.S_IMODE(resolved.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(resolved.parent.stat().st_mode), 0o700)
        repeated = self.vault.import_path(self.sample_source, media_type="application/x-other")
        self.assertEqual(repeated, self.sample)
        self.assertEqual(list(self.vault.imports_root.iterdir()), [])

        limited = SampleVault(
            self.root / "limited-vault",
            max_sample_bytes=len(self.sample_bytes) - 1,
            chunk_bytes=13,
        )
        with self.assertRaisesRegex(ValueError, "per-Sample"):
            limited.import_path(self.sample_source)
        self.assertEqual(list(limited.imports_root.iterdir()), [])

        total_limited = SampleVault(
            self.root / "total-limited-vault",
            max_vault_bytes=len(self.sample_bytes) - 1,
            chunk_bytes=19,
        )
        with self.assertRaisesRegex(ValueError, "total Vault"):
            total_limited.import_path(self.sample_source)
        self.assertEqual(list(total_limited.imports_root.iterdir()), [])

    def test_vault_rejects_symlink_and_recovers_incomplete_import(self) -> None:
        link = self.root / "sample-link"
        link.symlink_to(self.sample_source)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.vault.import_path(link)
        abandoned = self.vault.imports_root / "import-abandoned"
        abandoned.mkdir()
        (abandoned / "sample.bin").write_bytes(b"partial")
        receipt_path = self.vault.recover_incomplete_imports()
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["removedEntries"], ["import-abandoned"])
        self.assertEqual(list(self.vault.imports_root.iterdir()), [])

    def test_static_reports_become_bound_artifacts_and_findings(self) -> None:
        clam_report = self.root / "clamav.log"
        clam_report.write_text(
            "payload/wrapper.exe: Win.Test.MaliciousInstaller FOUND\n"
            "Known viruses: 100\n"
            "Engine version: 1.5.3\n"
            "Scanned files: 4\n"
            "Infected files: 1\n",
            encoding="utf-8",
        )
        auth_report = self.root / "authenticode.txt"
        auth_report.write_text(
            "=== SUMMARY: 3 files ===\n"
            "  VERIFIED_厂商B: 1\n"
            "  VERIFIED_OTHER: 1\n"
            "  UNSIGNED: 1\n"
            "  DIGEST_MISMATCH: 0\n"
            "=== UNSIGNED (all) ===\n"
            "  payload/wrapper.exe\n"
            "=== PARSE_ERROR / ERRORS ===\n",
            encoding="utf-8",
        )
        backend = LocalStaticEvaluationBackend(
            (
                FileIdentityAnalyzer(),
                ClamAvReportAnalyzer(clam_report),
                AuthenticodeReportAnalyzer(auth_report),
            ),
            work_root=self.root / "static-work",
        )
        result = self._run(backend)
        self.assertEqual(result.disposition, EvaluationDisposition.HIGH_RISK_CAPABILITY)
        self.assertTrue(result.residual_closed)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].behavior_class, "antivirus-signature-detection")
        evidence_path = Path(result.evidence_path)
        self.assertEqual(verify_evaluation_evidence(evidence_path), result.evidence_digest)
        self.assertEqual(
            verify_evaluation_operational_evidence(evidence_path),
            result.operational_evidence_digest,
        )
        manifest = json.loads((evidence_path / "bundle-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schemaVersion"], 2)
        self.assertEqual(len(manifest["artifacts"]), 2)
        self.assertEqual(list((self.root / "static-work").iterdir()), [])
        for path in evidence_path.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.sample_bytes, path.read_bytes())

        artifact_path = evidence_path / manifest["artifacts"][0]["path"]
        artifact_path.write_bytes(artifact_path.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValueError, "Artifact digest"):
            verify_evaluation_evidence(evidence_path)

    def test_artifact_bound_invalidates_trial_and_still_closes(self) -> None:
        report = self.root / "large-report.txt"
        report.write_bytes(b"x" * 1024)
        backend = LocalStaticEvaluationBackend(
            (
                FileIdentityAnalyzer(),
                ImportedReportAnalyzer(
                    report_id="large",
                    tool_id="tool:test",
                    report_path=report,
                    report_kind="test-report",
                ),
            ),
            work_root=self.root / "bounded-work",
        )
        result = self._run(backend, max_artifact_bytes=32, run_index=1)
        self.assertEqual(result.disposition, EvaluationDisposition.INVALID_TRIAL)
        self.assertTrue(result.residual_closed)
        self.assertEqual(list((self.root / "bounded-work").iterdir()), [])
        self.assertEqual(
            verify_evaluation_evidence(Path(result.evidence_path)), result.evidence_digest
        )

    def test_archive_inventory_detects_unsafe_paths_without_execution(self) -> None:
        fake_7z = self.root / "fake-7z"
        fake_7z.write_text(
            "#!/usr/bin/python3\n"
            "import sys\n"
            "if len(sys.argv) == 1:\n"
            "    print('7-Zip fake 1.0')\n"
            "else:\n"
            "    print('Path = ' + sys.argv[-1])\n"
            "    print('Type = 7z')\n"
            "    print('Path = safe/file.txt')\n"
            "    print('Path = ../escape.exe')\n",
            encoding="utf-8",
        )
        fake_7z.chmod(0o755)
        backend = LocalStaticEvaluationBackend(
            (FileIdentityAnalyzer(), ArchiveInventoryAnalyzer(fake_7z)),
            work_root=self.root / "archive-work",
        )
        result = self._run(backend, run_index=2)
        self.assertEqual(result.disposition, EvaluationDisposition.HIGH_RISK_CAPABILITY)
        self.assertEqual(result.findings[0].behavior_class, "archive-path-traversal")
        self.assertTrue(result.residual_closed)
        truth = (Path(result.evidence_path) / "events" / "world-truth.jsonl").read_text(
            encoding="utf-8"
        )
        self.assertIn('"sampleExecuted":false', truth)

    def test_quarantine_hardening_is_owner_only_and_preflighted(self) -> None:
        quarantine = self.root / "quarantine"
        nested = quarantine / "nested"
        nested.mkdir(parents=True)
        sample = nested / "sample.7z"
        sample.write_bytes(b"fixture")
        quarantine.chmod(0o755)
        nested.chmod(0o644)
        sample.chmod(0o755)
        receipt_path = self.root / "receipts" / "harden.json"
        receipt = harden_quarantine_tree(quarantine, receipt_path=receipt_path)
        self.assertEqual(receipt["directories"], 2)
        self.assertEqual(receipt["files"], 1)
        self.assertEqual(stat.S_IMODE(quarantine.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(sample.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        with self.assertRaisesRegex(FileExistsError, "receipt already exists"):
            harden_quarantine_tree(quarantine, receipt_path=receipt_path)

        unsafe = self.root / "unsafe-quarantine"
        unsafe.mkdir()
        regular = unsafe / "sample.bin"
        regular.write_bytes(b"fixture")
        regular.chmod(0o644)
        (unsafe / "link").symlink_to(regular)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            harden_quarantine_tree(unsafe)
        self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(regular.stat().st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
