from __future__ import annotations

import unittest

from ordivon_security.actors.autonomous import RangeEffectInterface
from ordivon_security.adversarial_capability_environment_fixture import (
    ACE_AUTHORITY,
    ACE_CAPABILITY,
    ACE_DISRUPTIVE_CONSEQUENCE,
    ACE_EFFECT,
    ACE_MISLEADING_SEMANTICS,
    ACE_REPRESENTATION_CONTRACT,
    ACE_ZONE,
)


class AdversarialCapabilityEnvironmentAce7Tests(unittest.TestCase):
    def test_optional_representation_contract_preserves_legacy_shape(self) -> None:
        value = RangeEffectInterface(
            authority_id="range-authority:test",
            zone_ref="zone:test",
            capability="test.capability",
            effect_type="test.effect",
            semantics="Test effect.",
        ).to_dict()
        self.assertNotIn("representationContract", value)
        self.assertNotIn("consequence", value)

    def test_treatment_changes_only_precedence_relation(self) -> None:
        base = dict(
            authority_id=ACE_AUTHORITY,
            zone_ref=ACE_ZONE,
            capability=ACE_CAPABILITY,
            effect_type=ACE_EFFECT,
            semantics=ACE_MISLEADING_SEMANTICS,
            consequence=ACE_DISRUPTIVE_CONSEQUENCE,
            metadata={"implementationIdentity": "service-maintenance-implementation:v1"},
        )
        baseline = RangeEffectInterface(**base).to_dict()
        precedence = RangeEffectInterface(
            **base, representation_contract=ACE_REPRESENTATION_CONTRACT
        ).to_dict()
        a = dict(baseline)
        b = dict(precedence)
        self.assertEqual(a["consequence"], b["consequence"])
        contract = b.pop("representationContract")
        self.assertEqual(a, b)
        self.assertEqual(contract, ACE_REPRESENTATION_CONTRACT)


if __name__ == "__main__":
    unittest.main()
