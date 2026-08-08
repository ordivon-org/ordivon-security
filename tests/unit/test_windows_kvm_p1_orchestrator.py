from __future__ import annotations

import unittest
from importlib.resources import files
from pathlib import Path


class WindowsKvmP1OrchestratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "p1-orchestrator.ps1"
                )
            )
        ).read_text(encoding="utf-8")
        cls.lowered = cls.source.lower()

    def test_orchestrator_has_fixed_control_surface(self) -> None:
        self.assertIn("maintained-control-self-test", self.source)
        self.assertIn("deny-all-at-hypervisor", self.source)
        self.assertIn("ntfs-inherited-execute-deny", self.source)
        self.assertIn("S-1-5-18", self.source)
        self.assertIn(
            "d29becd1409bab42bbba885b3e6db5623cedaf61d83d6c3b01ed7111e347d655",
            self.source,
        )
        self.assertIn("C:\\ProgramData\\Ordivon\\p1-observer.ps1", self.source)
        self.assertNotIn("installerPath", self.source)
        self.assertNotIn("executablePath", self.source)
        self.assertNotIn("-Command", self.source)

    def test_orchestrator_rejects_network_and_third_party_execution(self) -> None:
        for token in (
            "invoke-webrequest",
            "webclient",
            "bitsadmin",
            "start-bitstransfer",
            "http://",
            "https://",
            "new-object net.webclient",
        ):
            self.assertNotIn(token, self.lowered)
        self.assertIn("networkRequested = $false", self.source)
        self.assertIn("thirdPartySampleExecuted = $false", self.source)

    def test_derived_base_cli_seals_exact_orchestrator_identity(self) -> None:
        cli = (
            Path(__file__).parents[2]
            / "src"
            / "ordivon_security"
            / "cli_windows_kvm_p1_seal_derived_base.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "9f901eddccc3c0b510a39888d15d900748dccfe0c4516e94efad2798df3244e4",
            cli,
        )
        self.assertIn('WindowsKvmP1SealedResource("orchestrator", _ORCHESTRATOR)', cli)

    def test_orchestrator_binds_manifest_and_observer_ordering(self) -> None:
        self.assertIn("actualManifestDigest", self.source)
        self.assertIn("bindingDigestVerified", self.source)
        self.assertIn("manifestRunIdVerified", self.source)
        pre = self.source.index("Invoke-Observer -Phase pre")
        body = self.source.index("Copy-Item -LiteralPath $controlCanaryPath")
        post = self.source.index("Invoke-Observer -Phase post")
        self.assertLess(pre, body)
        self.assertLess(body, post)

    def test_public_production_orchestrator_acceptance_preserves_case_boundary(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-production-orchestrator-be4eae1.json"
        )
        index = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            index["status"],
            "accepted-maintained-production-orchestration-path",
        )
        self.assertEqual(
            index["implementationRevision"],
            "git:be4eae12953dd57e14fa578fabc7e0179e11b501",
        )
        self.assertIs(index["scope"]["productionControllerPathExercised"], True)
        self.assertIs(index["scope"]["productionOrchestratorPathExercised"], True)
        self.assertIs(index["scope"]["prePostObserverPathExercised"], True)
        self.assertIs(index["scope"]["selectiveExecutionControlExercised"], True)
        self.assertIs(index["scope"]["thirdPartySampleExecuted"], False)
        self.assertIs(index["scope"]["actualCaseAExecuted"], False)
        self.assertIs(index["scope"]["caseAExecutionAuthorized"], False)
        self.assertIs(index["scope"]["nestedMsiReachabilityProved"], False)
        self.assertEqual(
            index["sealedResources"]["observer"]["sha256"],
            "sha256:f66834322288251407cf50dc1f8c0986cb7bb6228f139d69cc128aa8fb421399",
        )
        self.assertIs(index["gates"]["controllerProductionPathVerified"], True)
        self.assertIs(index["gates"]["orchestratorPreObserverCompleted"], True)
        self.assertIs(index["gates"]["orchestratorPostObserverCompleted"], True)
        self.assertIs(index["gates"]["orchestratorSelectiveExecutionControl"], True)
        self.assertIs(index["gates"]["orchestratorObservationSequenceVerified"], True)
        self.assertIs(index["gates"]["qmpNoNetworkDevice"], True)
        self.assertIs(index["gates"]["providerErrorAbsent"], True)
        self.assertIs(index["gates"]["residualClosure"], True)


if __name__ == "__main__":
    unittest.main()
