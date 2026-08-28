from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

import ordivon_security
from ordivon_security.cli_surface import main as surface_cli_main
from ordivon_security.integrations import (
    HostAssignedDeepSeekHarnessTurnDriver,
    RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver,
)
from ordivon_security.world_boundary import (
    WorldEntityKvmDestination,
    WorldMessageInbox,
    WorldResourceInbox,
)


class SecuritySurfaceTests(unittest.TestCase):
    def test_package_root_stays_narrow_after_mixed_api_facade_retirement(self) -> None:
        expected = {
            "AdversarialWindowsRange",
            "ContestResult",
            "ContestRunner",
            "EvaluationResult",
            "EvaluationRunner",
            "EvaluationSpec",
            "RangeAuthority",
            "RangeEvent",
            "RangeSession",
            "RangeSessionSpec",
            "ResearchCorpus",
            "SacrificialWindowsRangeConfig",
            "ScenarioManifest",
            "WindowsKvmMachineConfig",
            "WindowsKvmMachineProvider",
            "security_ordinary_capability_preflight",
            "security_ordinary_surface_manifest",
            "security_surface_manifest",
        }
        self.assertEqual(set(ordivon_security.__all__), expected)
        for name in expected:
            self.assertIsNotNone(getattr(ordivon_security, name))

    def test_manifest_exposes_distinct_maturity_tiers(self) -> None:
        value = ordivon_security.security_surface_manifest()
        tiers = {entry["tier"] for entry in value["entries"]}
        self.assertEqual(
            tiers,
            {"constitution", "profile", "integration", "research-apparatus"},
        )
        self.assertNotIn("compatibilityFacade", value)
        names = {entry["name"] for entry in value["entries"]}
        self.assertIn("ResearchCorpus", names)
        self.assertIn("CA-LIC entitlement authority research", names)

    def test_current_surface_uses_exact_locators_and_separates_historical_apparatus(self) -> None:
        value = ordivon_security.security_surface_manifest()
        entries = value["entries"]
        self.assertTrue(all("*" not in str(entry["module"]) for entry in entries))
        names = {entry["name"] for entry in entries}
        self.assertNotIn("Acceptance runners", names)
        self.assertIn("Windows P1 admitted command family", names)
        historical = value["historicalResearch"]
        self.assertEqual(historical["authorityMap"], "docs/authority.md")
        self.assertEqual(historical["acceptanceEvidenceRoot"], "evidence/acceptance")
        self.assertEqual(historical["archivedRunnerRoot"], "fixtures/archive/runners")
        self.assertIn("do not claim current package", historical["rule"])

    def test_surface_cli_defaults_to_ordinary_navigation_without_experiment(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = surface_cli_main([])
        self.assertEqual(status, 0)
        value = json.loads(stdout.getvalue())
        self.assertEqual(value, ordivon_security.security_ordinary_surface_manifest())
        self.assertEqual(value["kind"], "ordivon.security-ordinary-surface")

    def test_surface_cli_preserves_explicit_full_maturity_surface(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = surface_cli_main(["--view", "full"])
        self.assertEqual(status, 0)
        value = json.loads(stdout.getvalue())
        self.assertEqual(value, ordivon_security.security_surface_manifest())
        self.assertEqual(value["kind"], "ordivon.security.agent-first-surface")

    def test_canonical_integration_imports_are_available(self) -> None:
        self.assertTrue(HostAssignedDeepSeekHarnessTurnDriver.__name__)
        self.assertTrue(RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver.__name__)

    def test_archived_c1i_n_consequence_runners_do_not_return_to_current_package(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        for module_name in (
            "cli_vanishing_consequence_acceptance.py",
            "cli_recipient_commit_gap_acceptance.py",
            "cli_intrinsic_idempotency_acceptance.py",
            "cli_compensation_acceptance.py",
            "cli_compensation_information_loss_acceptance.py",
            "cli_downstream_truth_failure_acceptance.py",
        ):
            self.assertFalse((package / module_name).exists(), module_name)

    def test_archived_ca1_ca6_research_runners_do_not_return_to_current_package(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        for module_name in (
            "cli_ca1_carrier_matrix.py",
            "cli_ca2_vulnerability_evidence.py",
            "cli_ca3_post_compromise_state.py",
            "cli_ca4_defensive_plane.py",
            "cli_ca6_tactical_adaptation.py",
        ):
            self.assertFalse((package / module_name).exists(), module_name)

    def test_archived_c1a_physical_proof_does_not_return_to_current_package(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        self.assertFalse((package / "cli_windows_kvm_c1a_acceptance.py").exists())

    def test_archived_c1d_historical_runner_does_not_return_to_current_package(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        retired = package / "cli_windows_kvm_fresh_controller_continuation_acceptance.py"
        self.assertFalse(retired.exists())

    def test_retired_c1c_one_shot_acceptance_runner_does_not_return(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        retired = package / "cli_windows_kvm_partial_materialization_acceptance.py"
        self.assertFalse(retired.exists())

    def test_retired_c1b_one_shot_acceptance_runner_does_not_return(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        self.assertFalse((package / "cli_windows_kvm_c1b_acceptance.py").exists())

    def test_retired_c1_one_shot_acceptance_runner_does_not_return(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        self.assertFalse((package / "cli_windows_kvm_c1_acceptance.py").exists())

    def test_retired_s6_one_shot_acceptance_runner_does_not_return(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        self.assertFalse((package / "cli_windows_kvm_s6_acceptance.py").exists())

    def test_retired_s3_one_shot_acceptance_runner_does_not_return(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        self.assertFalse((package / "cli_windows_kvm_s3_acceptance.py").exists())

    def test_retired_ace8_ace9_ace10_one_shot_runners_do_not_return(self) -> None:
        package = Path(ordivon_security.__file__).resolve().parent
        for module_name in (
            "cli_adversarial_capability_environment_ace8.py",
            "cli_adversarial_capability_environment_ace9.py",
            "cli_adversarial_capability_environment_ace10.py",
        ):
            self.assertFalse((package / module_name).exists(), module_name)

    def test_canonical_world_boundary_imports_are_available(self) -> None:
        self.assertTrue(WorldMessageInbox.__name__)
        self.assertTrue(WorldResourceInbox.__name__)
        self.assertTrue(WorldEntityKvmDestination.__name__)


class OrdinarySecuritySurfaceTests(unittest.TestCase):
    def test_ordinary_view_is_derived_and_excludes_research_apparatus(self) -> None:
        ordinary = ordivon_security.security_ordinary_surface_manifest()
        self.assertEqual(ordinary["kind"], "ordivon.security-ordinary-surface")
        names = {entry["name"] for entry in ordinary["surfaceEntries"]}
        self.assertEqual(
            names,
            {"EvidenceRecorder", "RangeSession", "ResearchCorpus", "Software Evaluation"},
        )
        self.assertNotIn("Acceptance runners", names)
        self.assertNotIn("Windows P1 admitted command family", names)
        self.assertNotIn("CA-LIC entitlement authority research", names)
        routes = {route["job"]: route["primarySurface"] for route in ordinary["routes"]}
        self.assertEqual(routes["provider-snapshot-currentness"], "ResearchCorpus")
        self.assertEqual(routes["software-or-endpoint-evaluation"], "Software Evaluation")
        vulnerability_route = next(
            route
            for route in ordinary["routes"]
            if route["job"] == "vulnerability-or-advisory-triage"
        )
        self.assertIn("mature external provider/tool", vulnerability_route["reason"])
        self.assertIn("does not own network fetch authority", vulnerability_route["reason"])
        self.assertEqual(
            vulnerability_route["nextOwnerOperation"],
            "security.ordinary.research.query",
        )
        sample_route = next(
            route for route in ordinary["routes"] if route["job"] == "sample-or-case-assessment"
        )
        self.assertEqual(sample_route["nextOwnerOperation"], "security.ordinary.research.query")
        operation_names = {item["operation"] for item in ordinary["ownerOperations"]}
        self.assertEqual(
            operation_names,
            {
                "security.ordinary.research.query",
                "security.ordinary.research.inspect",
                "security.ordinary.provider-currentness",
            },
        )

    def test_ordinary_view_does_not_grant_authority(self) -> None:
        ordinary = ordivon_security.security_ordinary_surface_manifest()
        self.assertIn("does not grant execution", ordinary["authorityBoundary"].lower())
        self.assertIn("reproduction/provenance", ordinary["researchBoundary"])


class OrdinarySecurityCapabilityPreflightTests(unittest.TestCase):
    def test_preflight_withdraws_inspect_until_exact_record_is_selected(self) -> None:
        value = ordivon_security.security_ordinary_capability_preflight()
        self.assertEqual(value["kind"], "ordivon.security.ordinary-capability-preflight")
        self.assertEqual(
            set(value["turnAddressableOwnerOperations"]),
            {"security.ordinary.research.query", "security.ordinary.provider-currentness"},
        )
        self.assertEqual(value["withdrawnOwnerOperations"], ["security.ordinary.research.inspect"])
        inspect = next(
            item for item in value["operations"] if item["operation"] == "security.ordinary.research.inspect"
        )
        self.assertEqual(inspect["mechanicalEligibility"], "input-required")
        self.assertFalse(inspect["turnAddressable"])

    def test_selected_current_record_recompiles_inspect_into_turn_surface(self) -> None:
        from ordivon_security.ordinary_memory import security_ordinary_research_query

        query = security_ordinary_research_query("EICAR")
        record_id = query["candidates"][0]["recordId"]
        value = ordivon_security.security_ordinary_capability_preflight(record_id=record_id)
        self.assertIn("security.ordinary.research.inspect", value["turnAddressableOwnerOperations"])
        inspect = next(
            item for item in value["operations"] if item["operation"] == "security.ordinary.research.inspect"
        )
        self.assertEqual(inspect["mechanicalEligibility"], "eligible")
        self.assertEqual(inspect["basis"]["recordId"], record_id)

    def test_unknown_record_fails_closed_without_withdrawing_independent_operations(self) -> None:
        value = ordivon_security.security_ordinary_capability_preflight(record_id="sample:does-not-exist")
        self.assertNotIn("security.ordinary.research.inspect", value["turnAddressableOwnerOperations"])
        self.assertIn("security.ordinary.research.query", value["turnAddressableOwnerOperations"])
        inspect = next(
            item for item in value["operations"] if item["operation"] == "security.ordinary.research.inspect"
        )
        self.assertEqual(inspect["mechanicalEligibility"], "ineligible")
        self.assertIn("failureClass", inspect["basis"])

    def test_missing_owner_sources_withdraw_mechanically_dependent_operations(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as raw:
            value = ordivon_security.security_ordinary_capability_preflight(root=Path(raw))
        self.assertEqual(value["turnAddressableOwnerOperations"], [])
        state = {item["operation"]: item for item in value["operations"]}
        self.assertEqual(state["security.ordinary.research.query"]["mechanicalEligibility"], "ineligible")
        self.assertEqual(state["security.ordinary.provider-currentness"]["mechanicalEligibility"], "ineligible")
        self.assertEqual(state["security.ordinary.research.inspect"]["mechanicalEligibility"], "ineligible")

    def test_record_id_is_not_silently_ignored_without_preflight(self) -> None:
        with self.assertRaises(SystemExit):
            surface_cli_main(["--record-id", "sample:test"])

    def test_preflight_cli_is_projection_only_and_does_not_add_a_new_console_script(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = surface_cli_main(["--preflight"])
        self.assertEqual(status, 0)
        value = json.loads(stdout.getvalue())
        self.assertEqual(value["truthRole"], "derived-owner-local-mechanical-eligibility-projection")
        self.assertIn("never grants Range/Evaluation execution authority", " ".join(value["rules"]))


if __name__ == "__main__":
    unittest.main()
