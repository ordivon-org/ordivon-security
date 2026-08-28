from __future__ import annotations

import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

from tests.support.windows_kvm_p1_orchestrator_probe import (
    _FIXTURE_ID,
    _compile_orchestrator_probe,
)


class WindowsKvmP1OrchestratorProbeTests(unittest.TestCase):
    def test_probe_has_no_arbitrary_execution_surface(self) -> None:
        source = Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "p1_orchestrator_probe.c"
                )
            )
        ).read_text(encoding="utf-8")
        self.assertIn("maintained-control-self-test", source)
        self.assertIn("deny-all-at-hypervisor", source)
        self.assertIn("ntfs-inherited-execute-deny", source)
        self.assertIn("thirdPartySampleExecution\\\":false", source)
        self.assertNotIn("--target", source)
        self.assertNotIn("installerPath", source)

    def test_probe_compiles_without_network_imports(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            output = Path(raw_root) / "p1-orchestrator-probe.exe"
            compilation = _compile_orchestrator_probe(output)
            self.assertEqual(compilation["fixtureId"], _FIXTURE_ID)
            self.assertEqual(compilation["networkImportMatches"], [])
            self.assertEqual(compilation["manifestAction"], "maintained-control-self-test")
            self.assertIs(compilation["thirdPartySampleExecution"], False)
            self.assertGreater(output.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
