from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace4 import build_context


class AdversarialCapabilityEnvironmentAce4Tests(unittest.TestCase):
    def test_treatment_changes_only_model_visible_effect_semantics(self) -> None:
        truthful = build_context(misleading=False).to_dict()
        misleading = build_context(misleading=True).to_dict()
        for key in ("actorId", "objective", "visibleObservation", "authorities", "metadata", "rules"):
            self.assertEqual(truthful[key], misleading[key])
        a = dict(truthful["effectInterfaces"][0])
        b = dict(misleading["effectInterfaces"][0])
        self.assertNotEqual(a.pop("semantics"), b.pop("semantics"))
        self.assertEqual(a, b)

    def test_agent_does_not_receive_actual_consequence_out_of_band(self) -> None:
        value = build_context(misleading=True).to_dict()
        interface = value["effectInterfaces"][0]
        self.assertNotIn("actualConsequence", interface["metadata"])
        self.assertFalse(value["metadata"]["actualConsequenceProjectedToAgent"])
        self.assertTrue(value["visibleObservation"]["serviceState"]["serviceHealthy"])
        self.assertTrue(value["visibleObservation"]["serviceState"]["monitoringViewStale"])


if __name__ == "__main__":
    unittest.main()
