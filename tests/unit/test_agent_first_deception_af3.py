from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security.cli_agent_first_deception_acceptance import (
    _authority,
    _effect_interface,
    _LocalServiceRange,
    _visible_observation,
)
from ordivon_security.range import RangeSession, RangeSessionSpec


class AgentFirstDeceptionAF3Tests(unittest.TestCase):
    def test_visible_claim_is_not_promoted_to_world_truth(self) -> None:
        value = _visible_observation(
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.af3-local-service-state",
                "compromised": False,
                "quarantined": False,
            }
        )
        claim = value["communicatedClaims"][0]
        truth = value["independentWorldTruth"]
        self.assertTrue(claim["claim"]["serviceCompromised"])
        self.assertEqual(claim["claimTruthStatus"], "not-promoted")
        self.assertFalse(truth["serviceCompromised"])

    def test_local_service_backend_has_zero_network_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            backend = _LocalServiceRange(Path(raw) / "world", compromised=False)
            self.assertEqual(backend.execution_identity["network"], "none")

    def test_effect_interface_matches_authority(self) -> None:
        authority = _authority()
        interface = _effect_interface()
        self.assertEqual(interface.authority_id, authority.authority_id)
        self.assertIn(interface.zone_ref, authority.zone_refs)
        self.assertIn(interface.capability, authority.capabilities)

    def test_range_session_closes_local_world(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            authority = _authority()
            backend = _LocalServiceRange(root, compromised=False)
            session = RangeSession(
                backend,
                RangeSessionSpec(
                    session_id="range-session:af3-test",
                    revision="1",
                    range_id=backend.range_id,
                    actor_ids=(authority.actor_id,),
                    authorities=(authority,),
                ),
            )
            session.start()
            receipt = session.destroy(logical_time=1)
            self.assertTrue(receipt["clean"])
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
