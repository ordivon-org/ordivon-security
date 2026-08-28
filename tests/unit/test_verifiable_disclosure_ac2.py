from __future__ import annotations

import unittest

from ordivon_security._canonical import canonical_digest
from ordivon_security.autonomous_communication_research_fixture import (
    AC0_ACTOR_A_ID,
    AC0_ACTOR_B_ID,
)
from ordivon_security.cli_verifiable_disclosure_ac2_acceptance import (
    _DISCLOSURE_CAPABILITY,
    _DISCLOSURE_EFFECT,
    _b_context,
    _controlled_disclosure_request,
    _normalize_b_context,
)


class VerifiableDisclosureAC2Tests(unittest.TestCase):
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

    def verified(self) -> dict[str, object]:
        return {
            "disclosureId": "verified-disclosure:ac2:a-signal:1",
            "sourceId": AC0_ACTOR_A_ID,
            "recipientId": AC0_ACTOR_B_ID,
            "property": "privateSignal",
            "value": 1,
            "truthAuthority": "owned-range-selective-disclosure",
            "verificationStatus": "verified-current-private-signal",
            "derivedFromSenderMessage": False,
        }

    def test_disclosure_request_does_not_carry_the_private_value(self) -> None:
        request = _controlled_disclosure_request()
        self.assertEqual(request.capability, _DISCLOSURE_CAPABILITY)
        self.assertEqual(request.effect_type, _DISCLOSURE_EFFECT)
        self.assertEqual(request.payload, {"recipientId": AC0_ACTOR_B_ID, "property": "privateSignal"})
        self.assertNotIn("value", request.payload)

    def test_b_sees_message_and_separate_verified_evidence(self) -> None:
        context = _b_context(self.state(), signal_b=1, verified_disclosure=self.verified())
        visible = context.visible_observation
        self.assertEqual(visible["messagesForActor"][0]["claimTruthStatus"], "not-promoted")
        self.assertEqual(
            visible["verifiedDisclosureForActor"]["truthAuthority"],
            "owned-range-selective-disclosure",
        )
        self.assertTrue(visible["evidenceRules"]["verifiedDisclosureIsAuthoritativeForNamedProperty"])
        self.assertFalse(visible["evidenceRules"]["ordinaryMessageContentIsWorldTruth"])

    def test_counterfactual_b_contexts_differ_only_private_b_signal(self) -> None:
        match = _b_context(self.state(), signal_b=1, verified_disclosure=self.verified()).to_dict()
        mismatch = _b_context(self.state(), signal_b=0, verified_disclosure=self.verified()).to_dict()
        self.assertNotEqual(canonical_digest(match), canonical_digest(mismatch))
        self.assertEqual(
            canonical_digest(_normalize_b_context(match)),
            canonical_digest(_normalize_b_context(mismatch)),
        )

    def test_input_has_no_trust_or_reputation_ontology(self) -> None:
        text = str(_b_context(self.state(), signal_b=1, verified_disclosure=self.verified()).to_dict()).lower()
        for token in ("trust", "reputation", "coalition", "collude", "organization"):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
