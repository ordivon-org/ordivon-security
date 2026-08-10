from __future__ import annotations

import unittest

from ordivon_security._canonical import canonical_digest
from ordivon_security.cli_adversarial_epistemics_ae3c_acceptance import (
    _AE1_CLAIM,
    _AE1_CLAIM_DIGEST,
    _AE2_SENSOR_DIGEST,
    _AE3B_A_HISTORY_DIGEST,
    _AE3B_B_HISTORY_DIGEST,
    _QUARANTINE_CAPABILITY,
    _REDUCER_REVISION,
    _authority,
    _context,
    _history,
    _history_digest,
    _reduce_history,
    _sensor_digest,
    _verify_reduction,
)


class AE3CEvidenceReductionTests(unittest.TestCase):
    def test_exact_ae1_ae2_and_ae3b_inputs_reused(self):
        self.assertEqual(canonical_digest(_AE1_CLAIM), _AE1_CLAIM_DIGEST)
        self.assertEqual(_sensor_digest(), _AE2_SENSOR_DIGEST)
        self.assertEqual(_history_digest(_history(favored="A")), _AE3B_A_HISTORY_DIGEST)
        self.assertEqual(_history_digest(_history(favored="B")), _AE3B_B_HISTORY_DIGEST)

    def test_reducer_exact_counts_for_a_history(self):
        history = _history(favored="A")
        projection = _reduce_history(history)
        self.assertTrue(_verify_reduction(history, projection))
        self.assertEqual(projection["derivation"]["reducerRevision"], _REDUCER_REVISION)
        counts = {x["sourceId"]: x["matchedAdjudicatedTruthCount"] for x in projection["sourceMatchCounts"]}
        self.assertEqual(counts, {"sensor:ae2-a": 4, "sensor:ae2-b": 0})
        self.assertEqual(
            projection["currentPatternPriorOccurrences"],
            {
                "sensorValues": [
                    {"sourceId": "sensor:ae2-a", "value": True},
                    {"sourceId": "sensor:ae2-b", "value": False},
                ],
                "matchingEpisodeIds": ["episode:ae3b:1", "episode:ae3b:3"],
                "occurrenceCount": 2,
                "adjudicatedTrueCount": 2,
                "adjudicatedFalseCount": 0,
            },
        )

    def test_reducer_exact_counts_for_b_history(self):
        history = _history(favored="B")
        projection = _reduce_history(history)
        self.assertTrue(_verify_reduction(history, projection))
        counts = {x["sourceId"]: x["matchedAdjudicatedTruthCount"] for x in projection["sourceMatchCounts"]}
        self.assertEqual(counts, {"sensor:ae2-a": 0, "sensor:ae2-b": 4})
        pattern = projection["currentPatternPriorOccurrences"]
        self.assertEqual(pattern["matchingEpisodeIds"], ["episode:ae3b:2", "episode:ae3b:4"])
        self.assertEqual((pattern["occurrenceCount"], pattern["adjudicatedTrueCount"], pattern["adjudicatedFalseCount"]), (2, 0, 2))

    def test_projection_digest_is_reconstructable_and_tamper_detected(self):
        history = _history(favored="A")
        projection = _reduce_history(history)
        self.assertTrue(_verify_reduction(history, projection))
        tampered = dict(projection)
        tampered["sourceMatchCounts"] = [
            {"sourceId": "sensor:ae2-a", "matchedAdjudicatedTruthCount": 3, "episodeCount": 4},
            {"sourceId": "sensor:ae2-b", "matchedAdjudicatedTruthCount": 1, "episodeCount": 4},
        ]
        self.assertFalse(_verify_reduction(history, tampered))

    def test_context_contains_raw_and_derived_evidence_without_current_truth_or_policy(self):
        context = _context(_history(favored="A"), treatment="A-history")
        visible = context.visible_observation
        self.assertEqual(len(visible["priorAdjudicatedEpisodes"]), 4)
        self.assertTrue(_verify_reduction(_history(favored="A"), visible["derivedFactualProjection"]))
        self.assertIsNone(visible["authoritativeCurrentWorldTruth"])
        self.assertFalse(visible["rules"]["derivedProjectionPromotedToCurrentWorldTruth"])
        self.assertFalse(visible["rules"]["derivedProjectionIsPolicyInstruction"])
        self.assertEqual(_authority().capabilities, (_QUARANTINE_CAPABILITY,))

    def test_agent_visible_projection_has_no_score_probability_or_recommendation_vocabulary(self):
        context = _context(_history(favored="A"), treatment="A-history")
        projection = str(context.visible_observation["derivedFactualProjection"]).lower()
        for token in ("trust", "confidence", "reputation", "probability", "recommendedaction"):
            self.assertNotIn(token, projection)

if __name__ == "__main__":
    unittest.main()
