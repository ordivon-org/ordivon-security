from __future__ import annotations

import unittest

from ordivon_security._canonical import canonical_digest
from ordivon_security.cli_adversarial_epistemics_ae3b_acceptance import (
 _AE1_CLAIM,
 _AE1_CLAIM_DIGEST,
 _AE2_SENSOR_DIGEST,
 _QUARANTINE_CAPABILITY,
 _authority,
 _context,
 _history,
 _history_digest,
 _sensor_digest,
)


class AE3BRawHistoryTests(unittest.TestCase):
 def test_accepted_fixtures_exact(self): self.assertEqual(canonical_digest(_AE1_CLAIM),_AE1_CLAIM_DIGEST); self.assertEqual(_sensor_digest(),_AE2_SENSOR_DIGEST)
 def test_histories_are_mirrored_with_same_truth_sequence(self):
  a,b=_history(favored="A"),_history(favored="B"); self.assertNotEqual(_history_digest(a),_history_digest(b)); self.assertEqual([x["adjudicatedWorldTruth"]["serviceCompromised"] for x in a],[x["adjudicatedWorldTruth"]["serviceCompromised"] for x in b]); self.assertTrue(all(x["sensorObservations"][0]["value"]==x["adjudicatedWorldTruth"]["serviceCompromised"] for x in a)); self.assertTrue(all(x["sensorObservations"][1]["value"]==x["adjudicatedWorldTruth"]["serviceCompromised"] for x in b))
 def test_no_derived_source_scores_in_raw_history(self):
  for history in (_history(favored="A"),_history(favored="B")):
   raw=str(history).lower(); self.assertTrue(all(token not in raw for token in ("trust","confidence","reliability","accuracy","score","priority")))
 def test_contexts_differ_only_by_raw_history_treatment(self):
  a=_context(_history(favored="A"),treatment="A-history"); b=_context(_history(favored="B"),treatment="B-history"); self.assertNotEqual(a.digest,b.digest); av=dict(a.visible_observation); bv=dict(b.visible_observation); av.pop("priorAdjudicatedEpisodes"); bv.pop("priorAdjudicatedEpisodes"); self.assertEqual(canonical_digest(av),canonical_digest(bv)); self.assertEqual(a.objective,b.objective); self.assertEqual(a.authority_snapshots,b.authority_snapshots); self.assertEqual(a.effect_interfaces,b.effect_interfaces)
 def test_no_adjudication_and_no_current_truth(self):
  c=_context(_history(favored="A"),treatment="A-history"); self.assertEqual(_authority().capabilities,(_QUARANTINE_CAPABILITY,)); self.assertIsNone(c.visible_observation["authoritativeCurrentWorldTruth"]); self.assertFalse(c.visible_observation["rules"]["authoritativeAdjudicationAvailable"])
 def test_agent_visible_context_does_not_prime_trust_family_vocabulary(self):
  c=_context(_history(favored="A"),treatment="A-history"); text=(str(c.visible_observation)+c.objective).lower(); self.assertTrue(all(token not in text for token in ("trust","confidence","reputation","reliability","accuracy")))
if __name__=="__main__": unittest.main()
