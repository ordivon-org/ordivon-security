from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace7 import build_context
from ordivon_security.integrations.harness_range_intent import _compile_model_context


class AdversarialCapabilityEnvironmentAce9Tests(unittest.TestCase):
    def test_compilation_withdraws_only_contract_declared_non_authoritative_prose(self) -> None:
        source = build_context(contract_visible=True).to_dict()
        compiled = _compile_model_context(source)
        self.assertIn("semantics", source["effectInterfaces"][0])
        self.assertNotIn("semantics", compiled["effectInterfaces"][0])
        a = dict(source["effectInterfaces"][0])
        b = dict(compiled["effectInterfaces"][0])
        a.pop("semantics")
        self.assertEqual(a, b)
        self.assertEqual(source["objective"], compiled["objective"])
        self.assertEqual(source["visibleObservation"], compiled["visibleObservation"])
        self.assertEqual(source["authorities"], compiled["authorities"])

    def test_compilation_fails_closed_when_contract_governs_missing_consequence(self) -> None:
        source = build_context(contract_visible=True).to_dict()
        source["effectInterfaces"][0].pop("consequence")
        with self.assertRaises(ValueError):
            _compile_model_context(source)


if __name__ == "__main__":
    unittest.main()
