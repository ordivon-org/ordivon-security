from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs" / "round1-full-experimental-report.md"
EVIDENCE = ROOT / "evidence" / "experiments" / "round1-20260730.json"


class Round1FullReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = REPORT.read_text()
        cls.evidence = json.loads(EVIDENCE.read_text())

    def test_report_binds_evidence_identity_and_trial_count(self) -> None:
        total = (
            self.evidence["micro_contest"]["trial_count"]
            + self.evidence["cage4"]["trial_count"]
            + self.evidence["model_ablations"]["trial_count"]
        )
        self.assertIn(self.evidence["evidence_id"], self.report)
        self.assertIn(f"**Retained Trials:** {total}", self.report)
        self.assertEqual(total, 84)

    def test_micro_table_matches_retained_evidence(self) -> None:
        expected = {
            "greedy-red": ("0.0188 ± 0.0000", "0.0000 ± 0.0000", "10.400 ± 0.000"),
            "opponent-aware-red": ("0.2274 ± 0.2919", "0.9333 ± 0.1380", "9.027 ± 1.334"),
            "committee-compromised-naive": ("0.0188 ± 0.0000", "0.0000 ± 0.0000", "10.400 ± 0.000"),
            "committee-compromised-compartmentalized": ("0.2274 ± 0.2919", "0.9333 ± 0.1380", "9.027 ± 1.334"),
        }
        for actor, fragments in expected.items():
            self.assertIn(actor, self.evidence["micro_contest"]["results"])
            for fragment in fragments:
                self.assertIn(fragment, self.report)

    def test_cage_table_matches_retained_evidence(self) -> None:
        for fragment in (
            "−65.0 ± 52.8",
            "17.2 ± 4.49",
            "−81.0 ± 59.9",
            "6.4 ± 3.78",
            "−73.0 ± 46.3",
            "16.8 ± 3.90",
            "−96.0 ± 60.4",
            "5.4 ± 2.88",
        ):
            self.assertIn(fragment, self.report)
        self.assertEqual(self.evidence["cage4"]["trial_count"], 20)

    def test_model_table_matches_final_retained_runs(self) -> None:
        for name, item in self.evidence["model_ablations"]["results"].items():
            self.assertFalse(item["outcome"]["details"]["objective_achieved"], name)
            self.assertIn(item["trace_digest"], self.report)
        for fragment in (
            "198.035 s",
            "292.483 s",
            "173.811 s",
            "157.745 s",
            "91,863",
            "77,134",
        ):
            self.assertIn(fragment, self.report)
        self.assertNotIn("Codex transcript | yes", self.report)
        self.assertNotIn("Codex strategic | yes", self.report)

    def test_report_preserves_claim_boundary(self) -> None:
        for fragment in (
            "does not establish general offensive or defensive capability",
            "No statistical significance test was performed",
            "one-seed model evaluation is inadequate",
            "Do not promote",
            "Custom Ordivon cyber range | Reject for next round",
        ):
            self.assertIn(fragment, self.report)


if __name__ == "__main__":
    unittest.main()
