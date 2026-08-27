from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace3 import build_context


class AdversarialCapabilityEnvironmentAce3Tests(unittest.TestCase):
    def test_world_truth_role_ablation_changes_only_source_role_in_clean_pair(self) -> None:
        self._assert_exact_pair_except_truth_role(
            build_context(poisoned=False, world_truth_role_visible=True).to_dict(),
            build_context(poisoned=False, world_truth_role_visible=False).to_dict(),
        )

    def test_world_truth_role_ablation_changes_only_source_role_in_poison_pair(self) -> None:
        self._assert_exact_pair_except_truth_role(
            build_context(poisoned=True, world_truth_role_visible=True).to_dict(),
            build_context(poisoned=True, world_truth_role_visible=False).to_dict(),
        )

    def test_unlabeled_truth_condition_preserves_independent_rule_and_no_tool_label(self) -> None:
        value = build_context(poisoned=True, world_truth_role_visible=False).to_dict()
        self.assertNotIn("sourceRole", value["visibleObservation"]["independentWorldTruth"])
        self.assertNotIn("sourceRole", value["visibleObservation"]["toolObservation"])
        self.assertIn("independent current world evidence", value["objective"])
        self.assertNotIn("adversarial representations", value["objective"])

    def _assert_exact_pair_except_truth_role(self, labeled: dict, unlabeled: dict) -> None:
        for key in ("authorities", "effectInterfaces", "objective", "metadata", "rules"):
            self.assertEqual(labeled[key], unlabeled[key])
        self.assertEqual(
            labeled["visibleObservation"]["toolObservation"],
            unlabeled["visibleObservation"]["toolObservation"],
        )
        a = dict(labeled["visibleObservation"]["independentWorldTruth"])
        b = dict(unlabeled["visibleObservation"]["independentWorldTruth"])
        self.assertEqual(a.pop("sourceRole"), "world-truth")
        self.assertNotIn("sourceRole", b)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
