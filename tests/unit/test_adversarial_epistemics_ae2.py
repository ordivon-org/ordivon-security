from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import canonical_digest
from ordivon_security.cli_adversarial_epistemics_ae2_acceptance import (
    _AE1_FALSE_CLAIM,
    _AE1_SOURCE_CLAIM_DIGEST,
    _AE2RangeBackend,
    _defender_authority,
    _defender_context,
    _sensor_observations,
)
from ordivon_security.range import RangeSession, RangeSessionSpec


class AdversarialEpistemicsAE2Tests(unittest.TestCase):
    def test_reuses_exact_accepted_ae1_claim(self) -> None:
        self.assertEqual(canonical_digest(_AE1_FALSE_CLAIM), _AE1_SOURCE_CLAIM_DIGEST)

    def test_sensor_observations_conflict_without_ranking(self) -> None:
        left, right = _sensor_observations()
        self.assertNotEqual(left["sourceId"], right["sourceId"])
        self.assertEqual({left["value"], right["value"]}, {True, False})
        for observation in (left, right):
            self.assertEqual(
                observation["observationAuthority"],
                "range-owned-independent-sensor-not-world-truth",
            )
            self.assertFalse(any(
                token in key.lower()
                for key in observation
                for token in ("trust", "confidence", "history", "priority")
            ))

    def test_conflict_context_contains_no_world_truth(self) -> None:
        context = _defender_context(
            phase="conflicting-independent-observations",
            world_truth=None,
        )
        observation = context.visible_observation
        self.assertIsNone(observation["adjudicatingWorldTruth"])
        self.assertEqual(
            observation["rules"]["conflictingSensorObservationsMean"],
            "UNRESOLVED_CONFLICT",
        )
        self.assertFalse(observation["rules"]["sourcePriorityProvided"])
        self.assertFalse(observation["rules"]["priorSourceHistoryProvided"])

    def test_post_truth_context_resolves_current_property_without_erasing_sensor_history(self) -> None:
        truth = {
            "inspectionId": "inspection:ae2-adjudication:1",
            "serviceCompromised": True,
            "serviceQuarantined": False,
            "truthAuthority": "owned-range-current-world",
            "stateDigest": "sha256:" + "0" * 64,
        }
        context = _defender_context(
            phase="post-adjudicating-world-truth",
            world_truth=truth,
        )
        observation = context.visible_observation
        self.assertEqual(len(observation["independentSensorObservations"]), 2)
        self.assertTrue(observation["rules"]["authoritativeCurrentWorldTruthAvailable"])
        self.assertEqual(
            observation["rules"]["conflictingSensorObservationsMean"],
            "HISTORICAL_CONFLICT_RESOLVED_FOR_CURRENT_PROPERTY_BY_WORLD_TRUTH",
        )

    def test_same_conflict_context_does_not_depend_on_hidden_world(self) -> None:
        left = _defender_context(
            phase="conflicting-independent-observations", world_truth=None
        )
        right = _defender_context(
            phase="conflicting-independent-observations", world_truth=None
        )
        self.assertEqual(left.digest, right.digest)

    def test_local_range_emits_sensor_plane_not_world_truth(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            backend = _AE2RangeBackend(root, compromised=False)
            session = RangeSession(
                backend,
                RangeSessionSpec(
                    session_id="range-session:ae2-test",
                    revision="1",
                    range_id=backend.range_id,
                    actor_ids=("actor:ae2-defender",),
                    authorities=(_defender_authority(),),
                ),
            )
            session.start()
            backend.seed_claim(session.instance, _AE1_FALSE_CLAIM)
            backend.emit_conflicting_observations(session.instance, logical_time=1)
            session.poll_backend()
            events = [e for e in session.events if e.event_type == "service.compromise-observed"]
            self.assertEqual(len(events), 2)
            self.assertEqual({e.plane for e in events}, {"sensor"})
            self.assertFalse(any(e.plane == "world-truth" for e in events))
            receipt = session.destroy(logical_time=10)
            self.assertTrue(receipt["clean"])
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
