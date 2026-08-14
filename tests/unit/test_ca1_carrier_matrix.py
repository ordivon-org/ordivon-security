from __future__ import annotations

import unittest
from importlib.resources import files
from pathlib import Path

from ordivon_security.cli_ca1_carrier_matrix import (
    _CARRIERS,
    _FIXTURE_PREFIX,
    _PRODUCT_CODE,
    _msi_wxs,
)


class Ca1CarrierMatrixTests(unittest.TestCase):
    def _resource(self, name: str) -> str:
        path = Path(
            str(files("ordivon_security").joinpath("resources", "windows_kvm", name))
        )
        return path.read_text(encoding="utf-8")

    def test_carrier_set_is_bounded_and_includes_native_control(self) -> None:
        self.assertEqual(
            _CARRIERS,
            (
                ("native", 0),
                ("powershell", 1),
                ("wsh-vbscript", 2),
                ("msi-installed-custom-action", 3),
            ),
        )
        self.assertEqual(_FIXTURE_PREFIX, "ordivon-ca1-carrier-probe-v1")

    def test_msi_uses_installed_exe_custom_action_and_fixed_cleanup_identity(self) -> None:
        xml = _msi_wxs(Path("/tmp/effect.exe"))
        self.assertIn(f"Id='{_PRODUCT_CODE}'", xml)
        self.assertIn("FileKey='EffectEXE'", xml)
        self.assertIn("After='InstallFinalize'", xml)
        self.assertIn("NOT Installed", xml)
        self.assertIn(r"C:\ProgramData\Ordivon\ca1\effect.marker", xml)
        self.assertIn(r"C:\ProgramData\Ordivon\ca1\effect-evidence.json", xml)
        self.assertEqual(xml.count("http://"), 1)  # WiX XML namespace only.
        self.assertIn("http://schemas.microsoft.com/wix/2006/wi", xml)
        self.assertNotIn("https://", xml)

    def test_effect_payload_is_local_bounded_same_effect_fixture(self) -> None:
        source = self._resource("ca1_effect_payload.c")
        self.assertIn("ordivon-ca1-same-effect-v1", source)
        self.assertIn("networkRequested\\\":false", source)
        self.assertIn("QueryFullProcessImageNameW", source)
        self.assertIn("ConvertSidToStringSidW", source)
        for prohibited in (
            "WinHttpOpen",
            "InternetOpen",
            "WSAStartup",
            "URLDownloadToFile",
        ):
            self.assertNotIn(prohibited, source)

    def test_probe_keeps_carrier_policy_and_semantic_effect_separate(self) -> None:
        source = self._resource("ca1_carrier_probe.c")
        self.assertIn("semanticEffectId", source)
        self.assertIn("ca1-same-effect-v1", source)
        self.assertIn("ExecutionPolicy Restricted", source)
        self.assertIn("officeWordProviderPresent", source)
        self.assertIn("msiInstalledPayloadRemoved", source)
        self.assertIn("thirdPartySampleExecuted\\\":false", source)
        self.assertIn("networkRequested\\\":false", source)
        self.assertNotIn("http://", source)
        self.assertNotIn("https://", source)

    def test_runner_authority_is_benign_no_network_only(self) -> None:
        runner_path = Path(str(files("ordivon_security").joinpath("cli_ca1_carrier_matrix.py")))
        source = runner_path.read_text(encoding="utf-8")
        self.assertIn('network_mode="deny-all"', source)
        self.assertIn('"execute-benign-fixture"', source)
        self.assertIn('"execute-third-party-sample"', source)
        self.assertIn('"credential-collection"', source)
        self.assertIn('"target-expansion"', source)
        self.assertIn("samePayloadBytesAcrossCompleted", source)
        self.assertNotIn("RangeActionGateway", source)


if __name__ == "__main__":
    unittest.main()
