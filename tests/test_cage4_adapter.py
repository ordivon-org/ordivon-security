from __future__ import annotations

import os
from pathlib import Path
import unittest

from ordivon_security_experiments.cage4 import (
    CAGE4_REVISION,
    Cage4BaselineSpec,
    run_cage4_baselines,
)


class Cage4AdapterTests(unittest.TestCase):
    def test_missing_source_fails_with_bootstrap_instruction(self) -> None:
        spec = Cage4BaselineSpec(
            experiment_id="EXP-CAGE-MISSING",
            source_path="/definitely/missing/cage4",
            source_revision=CAGE4_REVISION,
            seeds=(1,),
            steps=1,
            blue_policies=("sleep",),
            red_policies=("finite-state",),
        )
        with self.assertRaisesRegex(FileNotFoundError, "bootstrap_cage4"):
            run_cage4_baselines(spec, Path("/tmp/ordivon-cage4-missing-test"))

    @unittest.skipUnless(os.environ.get("ORDIVON_CAGE4_SOURCE"), "optional CAGE 4 source not configured")
    def test_pinned_external_source_runs_one_trial(self) -> None:
        source = Path(os.environ["ORDIVON_CAGE4_SOURCE"])
        spec = Cage4BaselineSpec(
            experiment_id="EXP-CAGE-SMOKE",
            source_path=str(source),
            source_revision=CAGE4_REVISION,
            seeds=(1,),
            steps=2,
            blue_policies=("sleep",),
            red_policies=("finite-state",),
        )
        output = Path("/tmp/ordivon-cage4-adapter-test")
        summary = run_cage4_baselines(spec, output)
        self.assertEqual(summary["trial_count"], 1)
        self.assertEqual(summary["source_revision"], CAGE4_REVISION)


if __name__ == "__main__":
    unittest.main()
