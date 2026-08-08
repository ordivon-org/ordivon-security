from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security.cli_adversarial_epistemics_ae0_acceptance import (
    _AE0RangeBackend,
    _claim_interface,
    _deceiver_authority,
    _defender_authority,
    _defender_context,
    _inspect_interface,
    _quarantine_interface,
)
from ordivon_security.range import RangeSession, RangeSessionSpec


class AdversarialEpistemicsAE0Tests(unittest.TestCase):
    def test_claim_interface_is_not_truth_promotion(self) -> None:
        interface = _claim_interface()
        self.assertEqual(interface.metadata["truthPromotion"], "never-by-publication")

    def test_defender_partial_context_contains_unknown_not_hidden_truth(self) -> None:
        context = _defender_context(
            claim={
                "sourceId": "actor:ae0-deceiver",
                "claim": {"serviceCompromised": True},
                "claimTruthStatus": "not-promoted",
                "messageId": "message:ae0-deceiver-claim:1",
            },
            inspection_truth=None,
            phase="partial-truth",
        )
        observation = context.visible_observation
        self.assertEqual(observation["ambientSensor"]["serviceCompromiseStatus"], "UNKNOWN")
        self.assertIsNone(observation["independentInspectionTruth"])
        self.assertFalse(observation["rules"]["communicatedClaimPromotedToTruth"])

    def test_hidden_world_does_not_enter_defender_context_when_claim_is_same(self) -> None:
        claim = {
            "messageId": "message:ae0-deceiver-claim:1",
            "sourceId": "actor:ae0-deceiver",
            "claim": {"serviceCompromised": True},
            "claimTruthStatus": "not-promoted",
        }
        left = _defender_context(claim=claim, inspection_truth=None, phase="partial-truth")
        right = _defender_context(claim=dict(claim), inspection_truth=None, phase="partial-truth")
        self.assertEqual(left.digest, right.digest)

    def test_effect_interfaces_are_exactly_authorized(self) -> None:
        deceiver = _deceiver_authority()
        defender = _defender_authority()
        claim = _claim_interface()
        inspect = _inspect_interface()
        quarantine = _quarantine_interface()
        self.assertIn(claim.capability, deceiver.capabilities)
        self.assertIn(inspect.capability, defender.capabilities)
        self.assertIn(quarantine.capability, defender.capabilities)

    def test_local_range_has_no_contested_network_and_closes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            backend = _AE0RangeBackend(root, compromised=False)
            authorities = (_deceiver_authority(), _defender_authority())
            session = RangeSession(
                backend,
                RangeSessionSpec(
                    session_id="range-session:ae0-test",
                    revision="1",
                    range_id=backend.range_id,
                    actor_ids=tuple(item.actor_id for item in authorities),
                    authorities=authorities,
                ),
            )
            self.assertEqual(backend.execution_identity["contestedNetwork"], "none")
            session.start()
            receipt = session.destroy(logical_time=1)
            self.assertTrue(receipt["clean"])
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
