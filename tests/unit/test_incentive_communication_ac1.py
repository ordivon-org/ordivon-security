from __future__ import annotations

import unittest

from ordivon_security._canonical import canonical_digest
from ordivon_security.autonomous_communication_research_fixture import (
    AC0_ACTOR_A_ID,
    AC0_ACTOR_B_ID,
)
from ordivon_security.cli_incentive_communication_ac1_acceptance import (
    _b_context,
    _normalize_b_context,
)
from ordivon_security.incentive_communication_research_fixture import (
    _FROZEN_A_REQUEST_DIGEST,
    _frozen_a_request,
    _public_incentive_structure,
)


class IncentiveCommunicationAC1Tests(unittest.TestCase):
    def state(self) -> dict[str, object]:
        return {
            "messages": [
                {
                    "messageId": "message:ac0:ac0-a:1",
                    "sourceId": AC0_ACTOR_A_ID,
                    "recipientId": AC0_ACTOR_B_ID,
                    "content": {"signal": 1},
                    "claimTruthStatus": "not-promoted",
                }
            ]
        }

    def test_frozen_a_request_is_exact_ac0_identity(self) -> None:
        request = _frozen_a_request()
        self.assertEqual(request.digest, _FROZEN_A_REQUEST_DIGEST)
        self.assertEqual(request.payload, {"recipientId": AC0_ACTOR_B_ID, "content": {"signal": 1}})

    def test_public_incentive_is_common_and_does_not_promote_truth(self) -> None:
        value = _public_incentive_structure()
        self.assertEqual(value["payoffAppliesTo"], [AC0_ACTOR_A_ID, AC0_ACTOR_B_ID])
        self.assertTrue(value["bothActorsObserveThisPayoffRule"])
        self.assertTrue(value["bothActorsObserveThatBothActorsObserveThisPayoffRule"])
        self.assertTrue(value["messageTruthStillNotGuaranteedByRule"])

    def test_receiver_counterfactuals_differ_only_in_private_signal(self) -> None:
        match = _b_context(self.state(), signal_b=1).to_dict()
        mismatch = _b_context(self.state(), signal_b=0).to_dict()
        self.assertNotEqual(canonical_digest(match), canonical_digest(mismatch))
        self.assertEqual(
            canonical_digest(_normalize_b_context(match)),
            canonical_digest(_normalize_b_context(mismatch)),
        )
        self.assertEqual(
            match["visibleObservation"]["publicIncentiveStructure"],
            mismatch["visibleObservation"]["publicIncentiveStructure"],
        )

    def test_agent_input_has_no_trust_or_social_state(self) -> None:
        text = str(_b_context(self.state(), signal_b=1).to_dict()).lower()
        for token in ("trust", "reputation", "coalition", "collude", "organization"):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
