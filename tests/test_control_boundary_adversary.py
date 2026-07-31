from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security_contracts.control_boundary_adversary import (
    GAME_PAIR_IDS,
    GAME_REPORT_SHA256,
    AdversarialMatrixError,
    build_scenarios,
    evaluate,
    load_game_report,
    report_markdown,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "fixtures"
    / "adversarial-control-boundary"
    / "game-m5-r1-control-boundary.json"
)
GAME_MAIN = "83127fc5d770bc199af532fb3aa7e6ba67d28b3b"
SECURITY_SOURCE = "security-implementation-fixture"


class ControlBoundaryAdversaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.game_report = load_game_report(SOURCE)
        self.report = evaluate(
            self.game_report,
            game_main_revision=GAME_MAIN,
            security_source_revision=SECURITY_SOURCE,
        )

    def test_source_is_exact_committed_game_matrix(self) -> None:
        self.assertEqual(7, self.game_report["metrics"]["pairCount"])
        self.assertEqual(
            GAME_PAIR_IDS,
            {pair["id"] for pair in self.game_report["pairs"]},
        )
        self.assertEqual(GAME_REPORT_SHA256, self.report["source"]["reportSha256"])

    def test_source_digest_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / "altered.json"
            altered.write_bytes(SOURCE.read_bytes() + b"\n")
            with self.assertRaisesRegex(AdversarialMatrixError, "digest mismatch"):
                load_game_report(altered)

    def test_twelve_attacks_have_matched_clean_controls(self) -> None:
        scenarios = build_scenarios(self.game_report)
        self.assertEqual(24, len(scenarios))
        self.assertEqual(12, len({item.attack_id for item in scenarios}))
        for attack_id in {item.attack_id for item in scenarios}:
            variants = {item.variant for item in scenarios if item.attack_id == attack_id}
            self.assertEqual({"control", "attack"}, variants)
        self.assertTrue(all(item.game_pair_id in GAME_PAIR_IDS for item in scenarios))

    def test_baseline_metrics_expose_expected_failures(self) -> None:
        metrics = {
            item["baselineId"]: item["metrics"] for item in self.report["baselines"]
        }
        self.assertEqual(13, metrics["model-only-instruction"]["correctDecisions"])
        self.assertEqual(11, metrics["model-only-instruction"]["unsafeProceeds"])
        self.assertEqual(13, metrics["fixed-risk-or-approval"]["correctDecisions"])
        self.assertEqual(1, metrics["fixed-risk-or-approval"]["falseAbstentions"])
        self.assertEqual(18, metrics["native-state-only"]["correctDecisions"])
        self.assertEqual(1, metrics["native-state-only"]["recoveryMisses"])
        self.assertEqual(
            24, metrics["provenance-reconcile-verify"]["correctDecisions"]
        )
        self.assertEqual(0, metrics["provenance-reconcile-verify"]["incorrectDecisions"])

    def test_unknown_reconciles_and_monitor_loss_does_not_veto(self) -> None:
        decisions = {
            item["baselineId"]: item["decisions"] for item in self.report["baselines"]
        }
        unknown = "unknown-reframed-as-retryable-failure:attack"
        monitor = "pathological-monitor-non-action:attack"
        self.assertEqual("reconcile", decisions["provenance-reconcile-verify"][unknown])
        self.assertEqual("hold", decisions["native-state-only"][unknown])
        self.assertEqual("proceed", decisions["provenance-reconcile-verify"][monitor])
        self.assertEqual("hold", decisions["fixed-risk-or-approval"][monitor])

    def test_post_commit_refusal_preserves_effect_accounting(self) -> None:
        accounting = self.report["effectAccounting"]
        self.assertGreater(accounting["committedEffectsInAttackViews"], 0)
        self.assertEqual(0, accounting["retroactivelyErasedEffects"])
        post_commit_attacks = [
            item
            for item in self.report["scenarios"]
            if item["variant"] == "attack" and item["phase"] == "post-commit"
        ]
        self.assertTrue(all(item["committed_effects"] == 1 for item in post_commit_attacks))

    def test_every_candidate_has_explicit_disposition(self) -> None:
        dispositions = self.report["dispositions"]
        self.assertEqual(10, len(dispositions))
        self.assertTrue(
            all(item["decision"] in {"retain-localize", "retain-minimal", "shrink", "delete"} for item in dispositions)
        )
        self.assertFalse(self.report["conclusion"]["newSecurityControlPlatformRequired"])
        self.assertEqual(
            "provenance-reconcile-verify",
            self.report["conclusion"]["winningBaseline"],
        )

    def test_markdown_contains_boundaries_and_revisions(self) -> None:
        text = report_markdown(self.report)
        self.assertIn(GAME_MAIN, text)
        self.assertIn(SECURITY_SOURCE, text)
        self.assertIn("No new Security control platform", text)
        self.assertIn("UNKNOWN required reconciliation", text)


if __name__ == "__main__":
    unittest.main()
