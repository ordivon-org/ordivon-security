from __future__ import annotations

import unittest

from ordivon_security.actors.autonomous import RangeEffectInterface
from ordivon_security.cli_adversarial_capability_environment_ace6 import build_context


class AdversarialCapabilityEnvironmentAce6Tests(unittest.TestCase):
    def test_optional_consequence_preserves_legacy_interface_shape(self) -> None:
        value = RangeEffectInterface(
            authority_id="range-authority:test",
            zone_ref="zone:test",
            capability="test.capability",
            effect_type="test.effect",
            semantics="Test effect.",
        ).to_dict()
        self.assertNotIn("consequence", value)

    def test_treatment_changes_only_first_class_consequence(self) -> None:
        absent = build_context(first_class_consequence=False).to_dict()
        visible = build_context(first_class_consequence=True).to_dict()
        for key in ("actorId", "objective", "visibleObservation", "authorities", "metadata", "rules"):
            self.assertEqual(absent[key], visible[key])
        a = dict(absent["effectInterfaces"][0])
        b = dict(visible["effectInterfaces"][0])
        self.assertNotIn("consequence", a)
        consequence = b.pop("consequence")
        self.assertEqual(a, b)
        self.assertTrue(consequence["serviceRestart"])
        self.assertFalse(consequence["readOnly"])


if __name__ == "__main__":
    unittest.main()
