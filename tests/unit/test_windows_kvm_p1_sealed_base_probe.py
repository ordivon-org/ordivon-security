from __future__ import annotations

import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

from tests.support.windows_kvm_p1_sealed_base_probe import (
    _FIXTURE_ID,
    _compile_sealed_base_probe,
)


class WindowsKvmP1SealedBaseProbeTests(unittest.TestCase):
    def test_probe_scope_is_fixed_to_accepted_sealed_resources(self) -> None:
        source = Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "p1_sealed_base_probe.c"
                )
            )
        ).read_text(encoding="utf-8")
        self.assertIn("C:\\\\ProgramData\\\\Ordivon\\\\p1-controller.exe", source)
        self.assertIn(
            "C:\\\\ProgramData\\\\Ordivon\\\\acceptance\\\\p1-execution-control-canary.exe",
            source,
        )
        self.assertIn("eb7e9874f1dc568721c826ea30e1b77f325254244564ca70381d2556f3d4388a", source)
        self.assertIn("d29becd1409bab42bbba885b3e6db5623cedaf61d83d6c3b01ed7111e347d655", source)
        self.assertNotIn('L"--target"', source)
        self.assertIn("thirdPartySampleExecuted\\\":false", source)

    def test_probe_compiles_without_network_imports(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            output = Path(raw_root) / "p1-sealed-base-probe.exe"
            compilation = _compile_sealed_base_probe(output)
            self.assertEqual(compilation["fixtureId"], _FIXTURE_ID)
            self.assertEqual(compilation["networkImportMatches"], [])
            self.assertIs(compilation["thirdPartySampleExecution"], False)
            targets = compilation["fixedSealedTargets"]
            self.assertEqual(
                targets["genericController"]["digest"],
                "sha256:eb7e9874f1dc568721c826ea30e1b77f325254244564ca70381d2556f3d4388a",
            )
            self.assertEqual(
                targets["executionControlCanary"]["digest"],
                "sha256:d29becd1409bab42bbba885b3e6db5623cedaf61d83d6c3b01ed7111e347d655",
            )
            self.assertGreater(output.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
