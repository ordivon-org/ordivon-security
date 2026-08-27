from __future__ import annotations

import unittest

from ordivon_security.actors.autonomous import RangeEffectInterface
from ordivon_security.cli_adversarial_capability_environment_ace7 import build_context


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
        baseline = build_context(contract_visible=False).to_dict()
        precedence = build_context(contract_visible=True).to_dict()
        for key in ("actorId", "objective", "visibleObservation", "authorities", "metadata", "rules"):
            self.assertEqual(baseline[key], precedence[key])
        a = dict(baseline["effectInterfaces"][0])
        b = dict(precedence["effectInterfaces"][0])
        self.assertEqual(a["consequence"], b["consequence"])
        contract = b.pop("representationContract")
        self.assertEqual(a, b)
        self.assertEqual(contract["decisionAuthoritativeField"], "consequence")
        self.assertEqual(contract["conflictDisposition"], "consequence-governs")
        self.assertEqual(contract["semanticsRole"], "descriptive-non-authoritative")


if __name__ == "__main__":
    unittest.main()
