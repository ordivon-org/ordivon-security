from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace1 import build_context


class AdversarialCapabilityEnvironmentAce1Tests(unittest.TestCase):
    def test_source_role_ablation_changes_only_tool_source_role_in_clean_pair(self) -> None:
        labeled = build_context(poisoned=False, source_role_visible=True).to_dict()
        unlabeled = build_context(poisoned=False, source_role_visible=False).to_dict()
        self._assert_exact_pair_except_source_role(labeled, unlabeled)

    def test_source_role_ablation_changes_only_tool_source_role_in_poison_pair(self) -> None:
        labeled = build_context(poisoned=True, source_role_visible=True).to_dict()
        unlabeled = build_context(poisoned=True, source_role_visible=False).to_dict()
        self._assert_exact_pair_except_source_role(labeled, unlabeled)

    def test_poison_changes_only_tool_message_inside_same_source_role_condition(self) -> None:
        clean = build_context(poisoned=False, source_role_visible=False).to_dict()
        poison = build_context(poisoned=True, source_role_visible=False).to_dict()
        self.assertEqual(clean["authorities"], poison["authorities"])
        self.assertEqual(clean["effectInterfaces"], poison["effectInterfaces"])
        self.assertEqual(clean["objective"], poison["objective"])
        self.assertEqual(clean["metadata"], poison["metadata"])
        self.assertEqual(
            clean["visibleObservation"]["independentWorldTruth"],
            poison["visibleObservation"]["independentWorldTruth"],
        )
        a = clean["visibleObservation"]["toolObservation"]
        b = poison["visibleObservation"]["toolObservation"]
        self.assertEqual(a["serviceHealthClaim"], b["serviceHealthClaim"])
        self.assertNotEqual(a["message"], b["message"])

    def _assert_exact_pair_except_source_role(self, labeled: dict, unlabeled: dict) -> None:
        self.assertEqual(labeled["authorities"], unlabeled["authorities"])
        self.assertEqual(labeled["effectInterfaces"], unlabeled["effectInterfaces"])
        self.assertEqual(labeled["objective"], unlabeled["objective"])
        self.assertEqual(labeled["metadata"], unlabeled["metadata"])
        self.assertEqual(
            labeled["visibleObservation"]["independentWorldTruth"],
            unlabeled["visibleObservation"]["independentWorldTruth"],
        )
        a = dict(labeled["visibleObservation"]["toolObservation"])
        b = dict(unlabeled["visibleObservation"]["toolObservation"])
        self.assertEqual(a.pop("sourceRole"), "untrusted-tool-output")
        self.assertNotIn("sourceRole", b)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
