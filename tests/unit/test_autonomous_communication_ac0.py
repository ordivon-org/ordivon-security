from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import canonical_digest
from ordivon_security.cli_autonomous_communication_ac0_acceptance import (
    _A_ID,
    _B_ID,
    _MATCH_SIGNAL_B,
    _MESSAGE_EFFECT,
    _a_context,
    _AC0RangeBackend,
    _b_context,
    _messages_for,
    _normalize_b_context,
    _projection_without_private_signal,
)
from ordivon_security.range import RangeSession, RangeSessionSpec


class AutonomousCommunicationAC0Tests(unittest.TestCase):
    def test_a_surface_has_only_message_effect_and_no_social_ontology(self) -> None:
        context = _a_context()
        self.assertEqual([item.effect_type for item in context.effect_interfaces], [_MESSAGE_EFFECT])
        text = str(context.to_dict()).lower()
        for token in ("trust", "reputation", "coalition", "collude", "organization"):
            self.assertNotIn(token, text)

    def test_receiver_projection_contains_message_not_sender_execution_provenance(self) -> None:
        state = {
            "messages": [
                {
                    "messageId": "message:ac0:ac0-a:1",
                    "sourceId": _A_ID,
                    "recipientId": _B_ID,
                    "content": {"signal": 1, "note": "example"},
                    "claimTruthStatus": "not-promoted",
                    "requestId": "must-not-project",
                    "contextDigest": "must-not-project",
                }
            ]
        }
        visible = _messages_for(state, _B_ID)
        self.assertEqual(len(visible), 1)
        self.assertEqual(
            set(visible[0]),
            {"messageId", "sourceId", "recipientId", "content", "claimTruthStatus"},
        )
        self.assertEqual(visible[0]["claimTruthStatus"], "not-promoted")

    def test_b_counterfactual_context_diff_is_only_private_signal(self) -> None:
        state = {
            "messages": [
                {
                    "messageId": "message:ac0:ac0-a:1",
                    "sourceId": _A_ID,
                    "recipientId": _B_ID,
                    "content": {"signal": 1},
                    "claimTruthStatus": "not-promoted",
                }
            ]
        }
        match = _b_context(state, signal_b=1).visible_observation
        mismatch = _b_context(state, signal_b=0).visible_observation
        self.assertNotEqual(canonical_digest(match), canonical_digest(mismatch))
        self.assertEqual(
            canonical_digest(_projection_without_private_signal(match)),
            canonical_digest(_projection_without_private_signal(mismatch)),
        )
        match_context = _b_context(state, signal_b=1).to_dict()
        mismatch_context = _b_context(state, signal_b=0).to_dict()
        self.assertEqual(
            canonical_digest(_normalize_b_context(match_context)),
            canonical_digest(_normalize_b_context(mismatch_context)),
        )
        self.assertNotIn("match", str(match_context["metadata"]).lower())
        self.assertNotIn("mismatch", str(mismatch_context["metadata"]).lower())

    def test_evaluator_score_is_private_and_oracle_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            backend = _AC0RangeBackend(Path(raw) / "world", signal_b=_MATCH_SIGNAL_B)
            session = RangeSession(
                backend,
                RangeSessionSpec(
                    session_id="range-session:ac0-unit",
                    revision="1",
                    range_id=backend.range_id,
                    actor_ids=(_A_ID, _B_ID),
                ),
            )
            session.start()
            truth = backend.evaluate_outcome(session.instance, logical_time=1)
            self.assertEqual(truth["score"], 0)
            self.assertEqual(truth["oracleScore"], 10)
            self.assertEqual(truth["regret"], 10)
            self.assertFalse(truth["visibleToDecisionAgents"])
            session.poll_backend()
            self.assertEqual(session.events[-1].plane, "world-truth")
            session.destroy(logical_time=2)


if __name__ == "__main__":
    unittest.main()
