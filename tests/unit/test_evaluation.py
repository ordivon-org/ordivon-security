from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation import (
    AuthorityManifest,
    EnvironmentIdentity,
    EvaluationDisposition,
    EvaluationResult,
    EvaluationRunner,
    EvaluationSpec,
    FixtureEvaluationBackend,
    GuardianPolicy,
    GuardianRecord,
    ObservationPlan,
    ObserverRecord,
    SampleIdentity,
    SampleVault,
    verify_evaluation_evidence,
    verify_evaluation_operational_evidence,
)


class EvaluationTrialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.vault = SampleVault(self.root / "vault")
        self.sample_bytes = b"UNIQUE_SAMPLE_PAYLOAD_NOT_EVIDENCE\x00\x01"
        self.sample = self.vault.import_bytes(
            self.sample_bytes,
            original_name="fixture.bin",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _spec(
        self,
        backend: FixtureEvaluationBackend,
        *,
        sample: SampleIdentity | None = None,
        environment_salt: str = "one",
        network_mode: str = "deny-all",
        allow_network: bool = False,
    ) -> EvaluationSpec:
        selected_sample = self.sample if sample is None else sample
        guardian = GuardianPolicy(
            policy_id="guardian-policy:test",
            revision="1",
            network_mode=network_mode,
            max_runtime_ms=1_000,
            max_memory_mib=128,
            max_processes=4,
            max_artifact_bytes=1_048_576,
            terminate_on=("unauthorized-network", "resource-limit"),
        )
        observation = ObservationPlan(
            plan_id="observation-plan:test",
            revision="1",
            channels=("sample", "observer", "guardian", "world-truth"),
            capture_memory="never",
            max_event_bytes=65_536,
        )
        environment = EnvironmentIdentity(
            environment_id=f"environment:test-{environment_salt}",
            provider_id=backend.provider_id,
            provider_revision="1",
            image_digest=canonical_digest({"image": environment_salt}),
            configuration_digest=canonical_digest({"configuration": environment_salt}),
            guardian_policy_digest=guardian.digest,
            observation_plan_digest=observation.digest,
        )
        authority = AuthorityManifest(
            authority_id="authority:test",
            revision="1",
            sample_digest=selected_sample.sha256,
            operator_id="operator:test",
            authorization_basis="Owned local fixture used for contract validation.",
            permitted_environment_ids=(environment.environment_id,),
            permitted_actions=("observe-only",),
            prohibited_actions=("execute-sample", "public-network"),
            max_runtime_ms=1_000,
            allow_network=allow_network,
        )
        return EvaluationSpec(
            evaluation_id="evaluation:test",
            revision="1",
            sample=selected_sample,
            authority=authority,
            environment=environment,
            guardian_policy=guardian,
            observation_plan=observation,
            requested_actions=("observe-only",),
            metadata={"sampleExecution": False},
        )

    def _run(
        self,
        backend: FixtureEvaluationBackend,
        *,
        run_index: int = 0,
        spec: EvaluationSpec | None = None,
    ) -> EvaluationResult:
        selected_spec = self._spec(backend) if spec is None else spec
        runner = EvaluationRunner(backend, self.vault, evidence_root=self.root / "evidence")
        return runner.run(selected_spec, run_index=run_index)

    def test_vault_import_resolve_and_purge(self) -> None:
        resolved = self.vault.resolve(self.sample)
        self.assertEqual(resolved.read_bytes(), self.sample_bytes)
        manifest = (resolved.parent / "manifest.json").read_bytes()
        self.assertNotIn(self.sample_bytes, manifest)
        repeated = self.vault.import_bytes(
            self.sample_bytes,
            media_type="application/x-other",
            original_name="another-name.bin",
        )
        self.assertEqual(repeated, self.sample)
        receipt = self.vault.purge(self.sample)
        self.assertFalse(resolved.exists())
        receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(receipt_value["sampleId"], self.sample.sample_id)
        self.assertTrue(receipt_value["objectExisted"])

    def test_dry_run_never_executes_sample_and_seals_evidence(self) -> None:
        backend = FixtureEvaluationBackend()
        result = self._run(backend)
        self.assertEqual(result.disposition, EvaluationDisposition.NO_ISSUE_OBSERVED)
        self.assertTrue(result.residual_closed)
        self.assertEqual(backend.create_calls, 1)
        self.assertEqual(backend.stage_calls, 1)
        self.assertEqual(backend.execute_calls, 1)
        self.assertEqual(backend.destroy_calls, 1)
        evidence_path = Path(result.evidence_path)
        self.assertEqual(verify_evaluation_evidence(evidence_path), result.evidence_digest)
        self.assertEqual(
            verify_evaluation_operational_evidence(evidence_path),
            result.operational_evidence_digest,
        )
        for path in evidence_path.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.sample_bytes, path.read_bytes())
        result_value = json.loads((evidence_path / "result.json").read_text(encoding="utf-8"))
        self.assertFalse(result_value["rawMetrics"]["fixture.sample_executed"])

    def test_tampered_vault_is_rejected_before_backend_creation(self) -> None:
        backend = FixtureEvaluationBackend()
        spec = self._spec(backend)
        self.vault.resolve(self.sample).write_bytes(b"tampered")
        result = self._run(backend, spec=spec)
        self.assertEqual(result.disposition, EvaluationDisposition.INVALID_TRIAL)
        self.assertEqual(backend.create_calls, 0)
        self.assertTrue(result.residual_closed)
        self.assertEqual(
            verify_evaluation_evidence(Path(result.evidence_path)), result.evidence_digest
        )

    def test_observer_finding_does_not_act_as_guardian(self) -> None:
        backend = FixtureEvaluationBackend(
            observer_records=(
                ObserverRecord(
                    channel="guest-observer",
                    event_type="behavior.process-injection",
                    payload={"target": "fixture-process"},
                ),
            )
        )
        result = self._run(backend)
        self.assertEqual(result.terminal_reason, "fixture-completed")
        self.assertEqual(result.disposition, EvaluationDisposition.HIGH_RISK_CAPABILITY)
        self.assertEqual(result.findings[0].behavior_class, "process-injection")
        self.assertTrue(result.residual_closed)

    def test_guardian_termination_is_preserved_without_inventing_finding(self) -> None:
        backend = FixtureEvaluationBackend(
            guardian_records=(
                GuardianRecord(
                    decision="terminate",
                    reason="unauthorized-network",
                    payload={"destinationClass": "outside-evaluation-network"},
                ),
            ),
            terminal_reason="guardian-terminated",
        )
        result = self._run(backend)
        self.assertEqual(result.disposition, EvaluationDisposition.SUSPICIOUS_INCONCLUSIVE)
        self.assertEqual(result.findings, ())
        guardian_log = Path(result.evidence_path) / "events" / "guardian.jsonl"
        self.assertIn(b"guardian.terminate", guardian_log.read_bytes())

    def test_backend_failure_still_destroys_and_seals_invalid_trial(self) -> None:
        backend = FixtureEvaluationBackend(fail_phase="execute")
        result = self._run(backend)
        self.assertEqual(result.disposition, EvaluationDisposition.INVALID_TRIAL)
        self.assertTrue(result.residual_closed)
        self.assertEqual(backend.destroy_calls, 1)
        self.assertTrue(result.terminal_reason.startswith("backend-or-admission-failure"))
        self.assertEqual(
            verify_evaluation_evidence(Path(result.evidence_path)), result.evidence_digest
        )

    def test_unclean_residual_invalidates_otherwise_successful_run(self) -> None:
        backend = FixtureEvaluationBackend(residual_clean=False)
        result = self._run(backend)
        self.assertEqual(result.disposition, EvaluationDisposition.INVALID_TRIAL)
        self.assertFalse(result.residual_closed)
        self.assertEqual(result.terminal_reason, "residual-closure-incomplete")

    def test_oversized_observer_record_invalidates_and_closes_run(self) -> None:
        backend = FixtureEvaluationBackend(
            observer_records=(
                ObserverRecord(
                    channel="guest-observer",
                    event_type="behavior.fixture",
                    payload={"value": "x" * 70_000},
                ),
            )
        )
        result = self._run(backend)
        self.assertEqual(result.disposition, EvaluationDisposition.INVALID_TRIAL)
        self.assertTrue(result.residual_closed)
        self.assertEqual(backend.destroy_calls, 1)

    def test_environment_change_changes_execution_identity(self) -> None:
        backend = FixtureEvaluationBackend()
        runner = EvaluationRunner(backend, self.vault, evidence_root=self.root / "evidence")
        first = self._spec(backend, environment_salt="one")
        second = self._spec(backend, environment_salt="two")
        self.assertNotEqual(
            canonical_digest(runner.execution_identity(first)),
            canonical_digest(runner.execution_identity(second)),
        )
        self.assertNotEqual(first.digest, second.digest)

    def test_network_mode_requires_explicit_authority(self) -> None:
        backend = FixtureEvaluationBackend()
        with self.assertRaisesRegex(ValueError, "does not permit"):
            self._spec(
                backend,
                network_mode="simulated-only",
                allow_network=False,
            )

    def test_evidence_tampering_is_detected(self) -> None:
        backend = FixtureEvaluationBackend(
            observer_records=(
                ObserverRecord(
                    channel="network-observer",
                    event_type="behavior.undeclared-network",
                    payload={"destination": "fixture.invalid"},
                ),
            )
        )
        result = self._run(backend)
        observer_log = Path(result.evidence_path) / "events" / "observer.jsonl"
        observer_log.write_bytes(
            observer_log.read_bytes().replace(b"fixture.invalid", b"other.invalid")
        )
        with self.assertRaisesRegex(ValueError, "file digest differs"):
            verify_evaluation_evidence(Path(result.evidence_path))


if __name__ == "__main__":
    unittest.main()
