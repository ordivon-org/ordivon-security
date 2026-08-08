from __future__ import annotations

import unittest
from importlib.resources import files
from pathlib import Path


class WindowsKvmP1ObserverRuntimeProbeTests(unittest.TestCase):
    def test_observer_runtime_is_channel_fail_soft(self) -> None:
        observer = Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "p1-observer.ps1"
                )
            )
        ).read_text(encoding="utf-8")
        self.assertIn("function Get-OptionalProperty", observer)
        self.assertIn("function Invoke-Channel", observer)
        self.assertIn("channelErrors = @($channelErrors)", observer)
        self.assertIn("degradedChannelCount = [int]$channelErrors.Count", observer)
        self.assertIn("$displayName = Get-OptionalProperty -InputObject $item -Name 'DisplayName'", observer)
        self.assertIn("function Convert-BoundedText", observer)
        self.assertIn("if ($property.Name -like 'PS*') { continue }", observer)
        self.assertIn("Select-Object -First $maxRecordEntries", observer)
        self.assertIn("ConvertTo-Json -Depth 8 -Compress", observer)
        self.assertNotIn("if ($null -ne $_.DisplayName)", observer)
        self.assertNotIn("values = $item | Select-Object *", observer)
        self.assertNotIn("Get-MpComputerStatus | Select-Object *", observer)

    def test_probe_matches_orchestrator_observer_contract(self) -> None:
        source = Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "p1_observer_runtime_probe.ps1"
                )
            )
        ).read_text(encoding="utf-8")
        self.assertIn("p1-observer.ps1", source)
        self.assertIn("e2aeb44c5a640b89ef95b86aebc4bfd0f97ef5eb01d3e09f39dbe77b8ff2c30f", source)
        self.assertIn("MaxFileEntries = 512", source)
        self.assertIn("MaxEventEntries = 128", source)
        self.assertIn("C:\\ProgramData\\Ordivon", source)
        self.assertIn("errorMessage = $_.Exception.Message", source)
        for token in ("Invoke-WebRequest", "WebClient", "Start-BitsTransfer", "http://", "https://"):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
