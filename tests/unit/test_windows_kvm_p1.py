from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ordivon_security.evaluation.windows_kvm_p1 import (
    _P1_INSPECT_ACTION,
    _P1_PREPARE_ACTION,
    WindowsKvmInstallerProfile,
    WindowsKvmP1MediaConfig,
    prepare_windows_kvm_installer_media,
    windows_kvm_p1_sample_disk_arguments,
)
from ordivon_security.evaluation.windows_kvm_p1_contracts import (
    WindowsKvmInstallerObservationProfile,
    WindowsKvmInstallerStaticDecision,
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsKvmP1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "sample.7z"
        self.source.write_bytes(b"authorized-installer-archive")
        self.profile = WindowsKvmInstallerProfile(
            profile_id="profile:windows-kvm-p1:test",
            revision="1",
            case_id="case:test-installer",
            archive_digest=_digest(self.source),
            archive_byte_length=self.source.stat().st_size,
            archive_name="installer.7z",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _tool(self, name: str, body: str) -> Path:
        path = self.root / name
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_public_目标产品B_media_index_does_not_authorize_execution(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-caseb-media-136a8a7.json"
        )
        index = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(index["status"], "superseded-by-static-rejection")
        self.assertIs(index["current"], False)
        self.assertIs(index["mediaRetained"], False)
        self.assertEqual(
            index["supersededBy"],
            "windows-kvm-p1-caseb-case-closeout-bf272ab.json",
        )
        self.assertIs(index["authorization"]["prepareAuthorizedMedia"], True)
        self.assertIs(index["authorization"]["attachToGuest"], False)
        self.assertIs(index["authorization"]["executeArchiveOrInstaller"], False)
        self.assertEqual(index["gate"]["embeddedReadbackIdentity"], "passed")
        self.assertEqual(index["gate"]["toolIdentity"], "passed")
        self.assertEqual(index["gate"]["preparationIdentity"], "passed")
        self.assertEqual(
            index["implementationRevision"],
            "git:136a8a71af63b6f37d31cc6b785441ac5cd9a8bc",
        )
        old_path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-caseb-media-bcac3cc.json"
        )
        old_index = __import__("json").loads(old_path.read_text(encoding="utf-8"))
        self.assertEqual(old_index["status"], "superseded-pre-provenance")
        self.assertEqual(old_index["supersededBy"], path.name)

    def test_目标产品B_static_decision_rejects_execution_profile(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "research"
            / "cases"
            / "windows-kvm-p1-caseb-static-entry.json"
        )
        value = __import__("json").loads(path.read_text(encoding="utf-8"))
        decision = WindowsKvmInstallerStaticDecision.from_dict(value)
        self.assertEqual(decision.outcome, "reject-execution-profile")
        self.assertIs(decision.execution_authorized, False)
        self.assertIs(decision.chain_complete, False)
        self.assertEqual(
            decision.identities["nestedMsi"],
            "sha256:ffc59cca203cc0eac7dc939bce70f4f2435536685fa097dca4b047875fd6a2d3",
        )
        self.assertEqual(
            decision.identities["downloaderScript"],
            "sha256:fe335766b60b18bfc4890e832a1dfff1e8d0b44bd0aa6059206f34cf7081c397",
        )
        self.assertGreater(len(decision.reasons), 2)
        profile_decision = value["profileDecision"]
        self.assertIsNone(profile_decision["installerRelativePath"])
        self.assertIs(profile_decision["attachToGuest"], False)
        self.assertIs(profile_decision["executeInstaller"], False)

    def test_目标产品B_causality_reassessment_keeps_unproven_edges_explicit(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-caseb-causality-r2.json"
        )
        value = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(value["status"], "accepted-static-causality-reassessment")
        self.assertIs(value["sample"]["identityReverified"], True)
        self.assertIs(value["sample"]["executedDuringReassessment"], False)
        self.assertEqual(
            value["wrapperBootstrapper"]["configuredSetupFile"],
            "目标产品B Resolve\\目标产品B.msi",
        )
        self.assertIs(value["wrapperBootstrapper"]["nestedArchiveConfiguredAsSetupFile"], False)
        self.assertEqual(value["outerMsi"]["nestedArchiveLiteralReferenceCount"], 0)
        self.assertEqual(value["outerMsi"]["nestedMsiLiteralReferenceCount"], 0)
        self.assertEqual(
            value["causality"]["primaryInstallationPath"]["status"],
            "statically-bound",
        )
        self.assertEqual(
            value["causality"]["containedMaliciousBranch"]["status"],
            "contained-reachability-unproven",
        )
        self.assertIs(value["causality"]["chainComplete"], False)
        self.assertIs(value["hostControlRevalidation"]["resolveExe"]["matchesPriorBaseline"], True)
        self.assertIs(value["hostControlRevalidation"]["intlDll"]["matchesPriorBaseline"], True)
        self.assertEqual(value["hostControlRevalidation"]["oneDriveStandaloneUpdateTaskMatches"], 0)
        self.assertEqual(
            value["historicalIsolatedDynamicEvidence"]["corehubExactBundleAttempts"]["acceptedCount"],
            0,
        )
        self.assertEqual(
            value["historicalIsolatedDynamicEvidence"]["corehubExactBundleAttempts"]["controllerCompletedCount"],
            0,
        )

    def test_installer_observation_profile_requires_complete_authority(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "research"
            / "profiles"
            / "windows-kvm-installer-observation-p1.json"
        )
        value = __import__("json").loads(path.read_text(encoding="utf-8"))
        profile = WindowsKvmInstallerObservationProfile.from_dict(value)
        self.assertEqual(profile.network_mode, "deny-all")
        self.assertIn("scheduled-tasks", profile.snapshot_domains)
        self.assertIn("bits-jobs", profile.snapshot_domains)
        self.assertIn("powershell-script-block", profile.event_channels)
        self.assertIn("qmp-topology", profile.event_channels)
        self.assertIs(profile.invariants["qmpNoNetworkAuthority"], True)
        self.assertIs(profile.invariants["residualClosure"], True)
        incomplete = dict(value)
        incomplete["snapshotDomains"] = ["files"]
        with self.assertRaisesRegex(ValueError, "snapshot domains are incomplete"):
            WindowsKvmInstallerObservationProfile.from_dict(incomplete)

    def test_public_目标产品B_case_closeout_rejects_execution_and_removes_media(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-caseb-case-closeout-bf272ab.json"
        )
        index = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(index["status"], "closed-rejected")
        self.assertEqual(index["decision"]["outcome"], "reject-execution-profile")
        self.assertIs(index["decision"]["executionAuthorized"], False)
        self.assertIs(index["decision"]["attachToGuest"], False)
        self.assertIs(index["decision"]["startWindows"], False)
        self.assertIs(index["decision"]["executeInstaller"], False)
        self.assertIs(index["decision"]["installOnHost"], False)
        self.assertIs(index["media"]["imageRetained"], False)
        self.assertIs(index["media"]["manifestRetained"], True)
        self.assertIs(index["scope"]["p1GenericObserverImplemented"], False)
        self.assertIs(index["scope"]["p1GenericThirdPartyExecutionAdmitted"], False)

    def test_public_static_gate_is_a_rejection_not_execution_admission(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-caseb-static-91f08e0.json"
        )
        index = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(index["status"], "accepted-rejection-decision")
        self.assertEqual(index["decision"]["outcome"], "reject-execution-profile")
        self.assertIs(index["decision"]["chainComplete"], False)
        self.assertIs(index["decision"]["executionAuthorized"], False)
        self.assertIsNone(index["decision"]["installerRelativePath"])
        self.assertIs(index["decision"]["attachToGuest"], False)
        self.assertIs(index["decision"]["executeInstaller"], False)

    def test_目标产品B_research_admission_does_not_reverse_product_rejection(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "research"
            / "cases"
            / "windows-kvm-p1-caseb-isolated-research-trial.json"
        )
        value = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            value["kind"],
            "ordivon.security.windows-kvm-isolated-research-admission",
        )
        self.assertEqual(value["productAdmission"]["status"], "rejected")
        self.assertIs(value["productAdmission"]["installOnHost"], False)
        self.assertEqual(value["researchAdmission"]["status"], "admitted-in-stages")
        self.assertEqual(
            value["researchAdmission"]["currentAction"],
            "verify-read-only-sample-media",
        )
        self.assertIs(value["researchAdmission"]["executeOrdivonVerifier"], True)
        self.assertIs(value["researchAdmission"]["executeThirdPartyCode"], False)
        self.assertIs(value["researchAdmission"]["sampleMediaReadOnly"], True)
        self.assertEqual(value["researchAdmission"]["networkMode"], "deny-all")

    def test_public_p1_controller_canary_preserves_execution_boundary(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-controller-canary-e011541.json"
        )
        index = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(index["status"], "accepted-maintained-controller-canary")
        self.assertEqual(
            index["implementationRevision"],
            "git:e01154192164a679b38ab5c56e1747f55ef1bf94",
        )
        self.assertIs(index["scope"]["maintainedCanary"], True)
        self.assertIs(index["scope"]["thirdPartySample"], False)
        self.assertIs(index["scope"]["actualCaseAExecuted"], False)
        self.assertIs(index["scope"]["controllerSealedInP1Base"], False)
        self.assertIs(index["scope"]["selectiveSecondaryBlocking"], False)
        self.assertIs(index["scope"]["caseAExecutionAuthorized"], False)
        self.assertIs(index["gates"]["jobObjectTreeOwned"], True)
        self.assertIs(index["gates"]["killOnJobCloseRootTerminated"], True)
        self.assertIs(index["gates"]["killOnJobCloseDescendantTerminated"], True)
        self.assertIs(index["gates"]["activeProcessLimitBlockedSecondary"], True)
        self.assertIs(index["gates"]["qmpNoNetworkDevice"], True)
        self.assertIs(index["gates"]["providerErrorAbsent"], True)
        self.assertIs(index["gates"]["residualClosure"], True)
        self.assertIs(index["blockingObservation"]["selectiveSecondaryBlocking"], False)
        self.assertEqual(index["execution"]["terminalReason"], "benign-fixture-completed")
        self.assertIs(index["execution"]["residualClosed"], True)

    def test_profile_does_not_authorize_execution_by_default(self) -> None:
        value = self.profile.to_dict()
        self.assertEqual(value["permittedActions"], [_P1_PREPARE_ACTION])
        self.assertNotIn(_P1_INSPECT_ACTION, value["permittedActions"])
        self.assertIs(value["executionAuthorized"], False)
        self.assertIs(value["deploymentAuthorized"], False)
        self.assertIs(value["evaluationAuthorized"], False)
        self.assertIs(value["hostModificationAuthorized"], False)
        with self.assertRaisesRegex(ValueError, "bind the installer path"):
            replace(self.profile, evaluation_authorized=True)

    def test_qemu_sample_disk_is_read_only_and_removable(self) -> None:
        args = windows_kvm_p1_sample_disk_arguments(Path("/sample.img"))
        joined = " ".join(args)
        self.assertIn("readonly=on", joined)
        self.assertIn("removable=on", joined)
        self.assertIn("serial=ORDIVON_P1", joined)

    def test_prepare_media_binds_source_and_embedded_bytes(self) -> None:
        mkntfs = self._tool("mkntfs", "exit 0")
        ntfscp = self._tool("ntfscp", "exit 0")
        ntfscat = self._tool("ntfscat", f"cat '{self.source}'")
        with patch(
            "ordivon_security.evaluation.windows_kvm_p1.security_source_identity",
            return_value={
                "componentId": "ordivon-security",
                "revision": "git:test",
                "revisionKind": "git-commit",
                "packageVersion": "test",
            },
        ):
            result = prepare_windows_kvm_installer_media(
                self.profile,
                self.source,
                WindowsKvmP1MediaConfig(
                    state_root=self.root / "state",
                    mkntfs_path=mkntfs,
                    ntfscp_path=ntfscp,
                    ntfscat_path=ntfscat,
                    overhead_mib=128,
                ),
            )
        self.assertEqual(result["status"], "prepared-not-executable")
        self.assertIs(result["executionAuthorized"], False)
        media = result["media"]
        assert isinstance(media, dict)
        self.assertIs(media["readOnly"], True)
        self.assertIs(media["removable"], True)
        self.assertTrue(Path(str(media["path"])).is_file())
        self.assertEqual(result["implementation"]["revision"], "git:test")
        self.assertEqual(set(result["tools"]), {"mkntfs", "ntfscp", "ntfscat"})
        for identity in result["tools"].values():
            self.assertTrue(identity["digest"].startswith("sha256:"))
            self.assertGreater(identity["byteLength"], 0)
        self.assertEqual(
            result["preparationIdentityDigest"],
            __import__(
                "ordivon_security._canonical", fromlist=["canonical_digest"]
            ).canonical_digest(result["preparationIdentity"]),
        )

    def test_prepare_media_rejects_wrong_source_and_cleans_state(self) -> None:
        wrong = self.root / "wrong.7z"
        wrong.write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "differs from the authorized"):
            prepare_windows_kvm_installer_media(
                self.profile,
                wrong,
                WindowsKvmP1MediaConfig(
                    state_root=self.root / "state",
                    mkntfs_path=self._tool("mkntfs2", "exit 0"),
                    ntfscp_path=self._tool("ntfscp2", "exit 0"),
                    ntfscat_path=self._tool("ntfscat2", "exit 0"),
                ),
            )
        self.assertFalse((self.root / "state" / "sample-media").exists())


if __name__ == "__main__":
    unittest.main()
