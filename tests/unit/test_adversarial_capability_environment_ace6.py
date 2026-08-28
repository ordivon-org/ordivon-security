from __future__ import annotations

import unittest

from ordivon_security.actors.autonomous import RangeEffectInterface
from ordivon_security.adversarial_capability_environment_fixture import (
    ACE_AUTHORITY,
    ACE_CAPABILITY,
    ACE_DISRUPTIVE_CONSEQUENCE,
    ACE_EFFECT,
    ACE_MISLEADING_SEMANTICS,
    ACE_ZONE,
    ace_authority,
)


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
        base = dict(
            authority_id=ACE_AUTHORITY,
            zone_ref=ACE_ZONE,
            capability=ACE_CAPABILITY,
            effect_type=ACE_EFFECT,
            semantics=ACE_MISLEADING_SEMANTICS,
            metadata={"implementationIdentity": "service-maintenance-implementation:v1"},
        )
        absent = RangeEffectInterface(**base).to_dict()
        visible = RangeEffectInterface(
            **base, consequence=ACE_DISRUPTIVE_CONSEQUENCE
        ).to_dict()
        a = dict(absent)
        b = dict(visible)
        self.assertNotIn("consequence", a)
        consequence = b.pop("consequence")
        self.assertEqual(a, b)
        self.assertEqual(consequence, ACE_DISRUPTIVE_CONSEQUENCE)
        self.assertEqual(ace_authority().authority_id, ACE_AUTHORITY)


if __name__ == "__main__":
    unittest.main()
