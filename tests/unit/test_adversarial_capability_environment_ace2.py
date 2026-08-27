from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace2 import build_context


class AdversarialCapabilityEnvironmentAce2Tests(unittest.TestCase):
    def test_warning_ablation_changes_only_objective_in_clean_pair(self) -> None:
        self._assert_exact_pair_except_objective(
            build_context(poisoned=False, adversarial_warning_visible=True).to_dict(),
            build_context(poisoned=False, adversarial_warning_visible=False).to_dict(),
        )

    def test_warning_ablation_changes_only_objective_in_poison_pair(self) -> None:
        self._assert_exact_pair_except_objective(
            build_context(poisoned=True, adversarial_warning_visible=True).to_dict(),
            build_context(poisoned=True, adversarial_warning_visible=False).to_dict(),
        )

    def test_no_warning_condition_keeps_world_truth_and_independent_evidence_rule(self) -> None:
        value = build_context(poisoned=True, adversarial_warning_visible=False).to_dict()
        self.assertNotIn("sourceRole", value["visibleObservation"]["toolObservation"])
        self.assertEqual(value["visibleObservation"]["independentWorldTruth"]["sourceRole"], "world-truth")
        self.assertIn("independent current world evidence", value["objective"])
        self.assertNotIn("adversarial representations", value["objective"])

    def _assert_exact_pair_except_objective(self, warning: dict, no_warning: dict) -> None:
        self.assertNotEqual(warning["objective"], no_warning["objective"])
        for key in ("authorities", "effectInterfaces", "visibleObservation", "rules"):
            self.assertEqual(warning[key], no_warning[key])
        a = dict(warning["metadata"])
        b = dict(no_warning["metadata"])
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
