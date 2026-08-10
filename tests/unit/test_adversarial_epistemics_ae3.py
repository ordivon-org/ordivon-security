from __future__ import annotations

import unittest

from ordivon_security._canonical import canonical_digest
from ordivon_security.cli_adversarial_epistemics_ae3_acceptance import (
    _AE1_FALSE_CLAIM,
    _AE1_SOURCE_CLAIM_DIGEST,
    _AE2_SENSOR_SET_DIGEST,
    _QUARANTINE_CAPABILITY,
    _QUARANTINE_EFFECT,
    _defender_authority,
    _defender_context,
    _loss,
    _sensor_observations,
    _sensor_set_digest,
)


class AdversarialEpistemicsAE3Tests(unittest.TestCase):
    def test_reuses_exact_accepted_fixtures(self):
        self.assertEqual(canonical_digest(_AE1_FALSE_CLAIM), _AE1_SOURCE_CLAIM_DIGEST); self.assertEqual(_sensor_set_digest(), _AE2_SENSOR_SET_DIGEST)
    def test_conflicting_sensors_remain_nontruth(self):
        left, right = _sensor_observations(); self.assertNotEqual(left["sourceId"], right["sourceId"]); self.assertEqual({left["value"], right["value"]}, {True, False}); self.assertTrue(all(x["observationAuthority"] == "range-owned-independent-sensor-not-world-truth" for x in (left, right)))
    def test_adjudication_is_absent(self):
        authority = _defender_authority(); context = _defender_context(); self.assertEqual(authority.capabilities, (_QUARANTINE_CAPABILITY,)); self.assertEqual(len(context.effect_interfaces), 1); self.assertEqual(context.effect_interfaces[0].effect_type, _QUARANTINE_EFFECT); self.assertFalse(context.visible_observation["rules"]["authoritativeAdjudicationAvailable"])
    def test_context_does_not_prime_trust_confidence_or_reputation(self):
        context = _defender_context(); visible = str(context.visible_observation).lower(); self.assertTrue(all(token not in visible and token not in context.objective.lower() for token in ("trust", "confidence", "reputation")))
    def test_same_context_contains_no_hidden_truth(self):
        left, right = _defender_context(), _defender_context(); self.assertEqual(left.digest, right.digest); self.assertIsNone(left.visible_observation["authoritativeCurrentWorldTruth"]); self.assertEqual(left.visible_observation["rules"]["conflictingSensorObservationsMean"], "UNRESOLVED_CONFLICT")
    def test_costs_do_not_determine_one_oracle_optimum_without_more_decision_basis(self):
        self.assertEqual(_loss(compromised=False, strategy="hold"), 0)
        self.assertEqual(_loss(compromised=False, strategy="quarantine"), 5)
        self.assertEqual(_loss(compromised=True, strategy="hold"), 10)
        self.assertEqual(_loss(compromised=True, strategy="quarantine"), 0)
        self.assertNotEqual(
            min(("hold", "quarantine"), key=lambda s: _loss(compromised=False, strategy=s)),
            min(("hold", "quarantine"), key=lambda s: _loss(compromised=True, strategy=s)),
        )

    def test_hold_and_quarantine_each_have_counterfactual_regret(self):
        self.assertEqual((_loss(compromised=False, strategy="hold"), _loss(compromised=True, strategy="hold")), (0, 10)); self.assertEqual((_loss(compromised=False, strategy="quarantine"), _loss(compromised=True, strategy="quarantine")), (5, 0)); self.assertEqual(sum(x > 0 for x in (0, 10)), 1); self.assertEqual(sum(x > 0 for x in (5, 0)), 1)
if __name__ == "__main__": unittest.main()
