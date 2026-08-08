from __future__ import annotations

import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

from ordivon_security.cli_windows_kvm_p1_generic_controller_canary import (
    _FIXTURE_ID,
    _compile_generic_controller,
)


class WindowsKvmP1GenericControllerTests(unittest.TestCase):
    def test_source_keeps_controller_scope_narrow(self) -> None:
        source = Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "p1_controller.c"
                )
            )
        ).read_text(encoding="utf-8")
        self.assertIn("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", source)
        self.assertIn("BCryptHashData", source)
        self.assertIn("C:\\\\ProgramData\\\\Ordivon\\\\p1-orchestrator.ps1", source)
        self.assertNotIn('L"--target"', source)
        self.assertIn("--manifest-digest", source)
        self.assertIn("--timeout-ms", source)
        self.assertIn("ordivon-p1-controller-selftest-v1", source)

    def test_generic_controller_compiles_without_network_imports(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            output = Path(raw_root) / "p1-controller.exe"
            compilation = _compile_generic_controller(output)
            self.assertEqual(compilation["fixtureId"], _FIXTURE_ID)
            self.assertEqual(compilation["networkImportMatches"], [])
            self.assertEqual(
                compilation["productionInterface"]["target"],
                "sealed-p1-orchestrator-only",
            )
            self.assertIs(
                compilation["productionInterface"]["arbitraryExecutableTarget"], False
            )
            self.assertTrue(output.is_file())
            self.assertGreater(output.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
