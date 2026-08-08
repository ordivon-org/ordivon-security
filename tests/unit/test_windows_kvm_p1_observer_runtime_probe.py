from __future__ import annotations

import unittest
from importlib.resources import files
from pathlib import Path


class WindowsKvmP1ObserverRuntimeProbeTests(unittest.TestCase):
    def test_probe_matches_orchestrator_observer_contract(self) -> None:
        source = Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "p1_observer_runtime_probe.ps1"
                )
            )
        ).read_text(encoding="utf-8")
        self.assertIn("p1-observer.ps1", source)
        self.assertIn("efeb283d513bfa9f59b4869b1b3385dad881013d64cfe65d3344c864879753d0", source)
        self.assertIn("MaxFileEntries = 512", source)
        self.assertIn("MaxEventEntries = 128", source)
        self.assertIn("C:\\ProgramData\\Ordivon", source)
        self.assertIn("errorMessage = $_.Exception.Message", source)
        for token in ("Invoke-WebRequest", "WebClient", "Start-BitsTransfer", "http://", "https://"):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
