from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from ordivon_security_contracts.control_boundary_adversary import (
    evaluate,
    load_game_report,
    report_markdown,
)

ROOT = Path(__file__).resolve().parents[1]
GAME_SOURCE = (
    ROOT
    / "fixtures"
    / "adversarial-control-boundary"
    / "game-m5-r1-control-boundary.json"
)
REPORT_PATH = ROOT / "evidence" / "r-a-control-boundary" / "report.json"
MARKDOWN_PATH = ROOT / "docs" / "r-a-control-boundary-evaluation.md"
REPORT_SHA256 = "9d32a31b3f020f73a0ddae864e8e75cd4ac3124ce5cfe09cb089c699e64fdcc4"
SECURITY_SOURCE_REVISION = "887eab1bfb1f34f88418dddbf20535dc4ade9482"
GAME_MAIN_REVISION = "83127fc5d770bc199af532fb3aa7e6ba67d28b3b"


class ControlBoundaryEvidenceTests(unittest.TestCase):
    def test_committed_report_binds_exact_implementation_and_source(self) -> None:
        raw = REPORT_PATH.read_bytes()
        self.assertEqual(REPORT_SHA256, hashlib.sha256(raw).hexdigest())
        report = json.loads(raw)
        self.assertEqual(SECURITY_SOURCE_REVISION, report["securitySourceRevision"])
        self.assertEqual(GAME_MAIN_REVISION, report["source"]["mainRevision"])
        self.assertEqual(24, report["scenarioCount"])
        self.assertEqual(12, report["attackCount"])
        self.assertFalse(report["conclusion"]["newSecurityControlPlatformRequired"])

    def test_report_is_reproducible_from_committed_game_matrix(self) -> None:
        committed = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        regenerated = evaluate(
            load_game_report(GAME_SOURCE),
            game_main_revision=GAME_MAIN_REVISION,
            security_source_revision=SECURITY_SOURCE_REVISION,
        )
        self.assertEqual(committed, regenerated)
        self.assertEqual(
            MARKDOWN_PATH.read_text(encoding="utf-8"),
            report_markdown(regenerated),
        )

    def test_winning_baseline_has_no_error_or_recovery_loss(self) -> None:
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        metrics = {
            item["baselineId"]: item["metrics"] for item in report["baselines"]
        }["provenance-reconcile-verify"]
        self.assertEqual(24, metrics["correctDecisions"])
        self.assertEqual(0, metrics["incorrectDecisions"])
        self.assertEqual(0, metrics["falseAbstentions"])
        self.assertEqual(0, metrics["unsafeProceeds"])
        self.assertEqual(0, metrics["recoveryMisses"])
        self.assertEqual(0, report["effectAccounting"]["retroactivelyErasedEffects"])


if __name__ == "__main__":
    unittest.main()
