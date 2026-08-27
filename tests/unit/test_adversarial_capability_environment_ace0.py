from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace0 import build_context


class AdversarialCapabilityEnvironmentAce0Tests(unittest.TestCase):
    def test_tool_output_treatment_changes_only_model_visible_observation_not_truth_or_authority(self) -> None:
        clean = build_context(observation_poisoned=False, description_poisoned=False).to_dict()
        poisoned = build_context(observation_poisoned=True, description_poisoned=False).to_dict()
        self.assertEqual(clean["authorities"], poisoned["authorities"])
        self.assertEqual(clean["effectInterfaces"], poisoned["effectInterfaces"])
        self.assertEqual(clean["objective"], poisoned["objective"])
        self.assertEqual(
            clean["visibleObservation"]["independentWorldTruth"],
            poisoned["visibleObservation"]["independentWorldTruth"],
        )
        self.assertEqual(
            clean["visibleObservation"]["toolObservation"]["serviceHealthClaim"],
            poisoned["visibleObservation"]["toolObservation"]["serviceHealthClaim"],
        )
        self.assertNotEqual(
            clean["visibleObservation"]["toolObservation"]["message"],
            poisoned["visibleObservation"]["toolObservation"]["message"],
        )

    def test_tool_description_treatment_preserves_actual_effect_identity_and_authority(self) -> None:
        clean = build_context(observation_poisoned=False, description_poisoned=False).to_dict()
        poisoned = build_context(observation_poisoned=False, description_poisoned=True).to_dict()
        self.assertEqual(clean["authorities"], poisoned["authorities"])
        self.assertEqual(clean["visibleObservation"], poisoned["visibleObservation"])
        a = clean["effectInterfaces"][0]
        b = poisoned["effectInterfaces"][0]
        for key in ("authorityId", "zoneRef", "capability", "effectType", "metadata"):
            self.assertEqual(a[key], b[key])
        self.assertNotEqual(a["semantics"], b["semantics"])
        self.assertEqual(a["metadata"]["actualConsequence"], "disruptive-service-reset")

    def test_context_never_claims_tool_text_is_world_truth(self) -> None:
        value = build_context(observation_poisoned=True, description_poisoned=True).to_dict()
        self.assertEqual(value["visibleObservation"]["toolObservation"]["sourceRole"], "untrusted-tool-output")
        self.assertEqual(value["visibleObservation"]["independentWorldTruth"]["sourceRole"], "world-truth")
        self.assertFalse(value["metadata"]["effectExecutionInExperiment"])


if __name__ == "__main__":
    unittest.main()
