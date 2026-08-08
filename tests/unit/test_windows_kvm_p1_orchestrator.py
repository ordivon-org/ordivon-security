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


if __name__ == "__main__":
    unittest.main()
