from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security.cli_adversarial_epistemics_ae1_acceptance import (
    _AE1RangeBackend,
    _deceiver_authority,
    _defender_authority,
    _defender_context,
    _inspect_interface,
    _quarantine_interface,
)
from ordivon_security.range import RangeSession, RangeSessionSpec


class AdversarialEpistemicsAE1Tests(unittest.TestCase):
    def test_pending_context_contains_no_compromise_truth(self) -> None:
        claim = {
            "messageId": "message:ae1-deceiver-claim:1",
            "sourceId": "actor:ae1-deceiver",
            "claim": {"serviceCompromised": True},
            "claimTruthStatus": "not-promoted",
        }
        pending = {
            "inspectionId": "inspection:ae1:1",
            "status": "pending",
            "truthAvailable": False,
            "decisionOpportunitiesUntilTruth": 1,
            "duplicate": False,
            "duplicateAcceleratesTruth": False,
        }
        context = _defender_context(
            claim=claim,
            phase="inspection-pending",
            inspection_status=pending,
            inspection_truth=None,
        )
        observation = context.visible_observation
        self.assertIsNone(observation["independentInspectionTruth"])
        self.assertEqual(observation["ambientSensor"]["serviceCompromiseStatus"], "UNKNOWN")
        self.assertFalse(observation["inspectionStatus"]["truthAvailable"])

    def test_pending_context_is_hidden_world_independent(self) -> None:
        claim = {
            "messageId": "message:ae1-deceiver-claim:1",
            "sourceId": "actor:ae1-deceiver",
            "claim": {"serviceCompromised": True},
            "claimTruthStatus": "not-promoted",
        }
        pending = {
            "inspectionId": "inspection:ae1:1",
            "status": "pending",
            "truthAvailable": False,
            "decisionOpportunitiesUntilTruth": 1,
            "duplicate": False,
            "duplicateAcceleratesTruth": False,
        }
        left = _defender_context(
            claim=claim, phase="inspection-pending", inspection_status=pending, inspection_truth=None
        )
        right = _defender_context(
            claim=dict(claim),
            phase="inspection-pending",
            inspection_status=dict(pending),
            inspection_truth=None,
        )
        self.assertEqual(left.digest, right.digest)

    def test_inspection_declares_delay_and_duplicate_non_acceleration(self) -> None:
        interface = _inspect_interface()
        self.assertEqual(interface.metadata["truthDelayDecisionOpportunities"], 1)
        self.assertFalse(interface.metadata["duplicateAcceleratesTruth"])

    def test_quarantine_does_not_reveal_compromise_truth(self) -> None:
        interface = _quarantine_interface()
        self.assertFalse(interface.metadata["revealsCompromiseTruth"])

    def test_local_range_closes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            backend = _AE1RangeBackend(root, compromised=False)
            session = RangeSession(
                backend,
                RangeSessionSpec(
                    session_id="range-session:ae1-test",
                    revision="1",
                    range_id=backend.range_id,
                    actor_ids=("actor:ae1-deceiver", "actor:ae1-defender"),
                    authorities=(_deceiver_authority(), _defender_authority()),
                ),
            )
            session.start()
            receipt = session.destroy(logical_time=1)
            self.assertTrue(receipt["clean"])
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
