from __future__ import annotations

import unittest

from ordivon_security.finalized_range_intent_research_fixture import (
    _can_materialize_security_decision,
    _FinalizedRangeIntentBridge,
)


class ReviewedRangeIntentIF1Tests(unittest.TestCase):
    class FakeObservation:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    class FakeError(RuntimeError):
        def __init__(self, message: str, *, kind: str) -> None:
            super().__init__(message)
            self.kind = kind

    def bridge(self) -> _FinalizedRangeIntentBridge:
        return _FinalizedRangeIntentBridge(
            catalog=object(),
            observation_type=self.FakeObservation,
            max_effect_requests=8,
            max_intent_revisions=4,
            bridge_identity={"kind": "test-if1"},
            tool_bridge_error_type=self.FakeError,
            model_correctable_kind="model_correctable",
        )

    @staticmethod
    def pending_call(requests: list[dict[str, object]] | None = None):
        class Pending:
            name = "submit_range_intents"
            arguments = {"requests": [] if requests is None else requests}
            tool_call_id = "call:pending"

        return Pending()

    @staticmethod
    def review_call(revision: int):
        class Review:
            name = "review_pending_intent"
            arguments = {"expectedRevision": revision}
            tool_call_id = "call:review"

        return Review()

    @staticmethod
    def finalize_call(revision: int, digest: str):
        class Finalize:
            name = "finalize_range_intent"
            arguments = {"expectedRevision": revision, "expectedPendingDigest": digest}
            tool_call_id = "call:finalize"

        return Finalize()

    def test_pending_readback_then_finalize_exact_snapshot(self) -> None:
        bridge = self.bridge()
        pending = bridge.execute(self.pending_call(), step_id="step:1")
        review = bridge.execute(self.review_call(1), step_id="step:2")
        digest = review.kwargs["structured_content"]["reviewedPendingDigest"]
        final = bridge.execute(self.finalize_call(1, digest), step_id="step:3")
        self.assertEqual(bridge.intent_revisions, [[]])
        self.assertEqual(bridge.review_count, 1)
        self.assertEqual(bridge.reviewed_revision, 1)
        self.assertEqual(bridge.reviewed_digest, digest)
        self.assertEqual(bridge.finalized_revision, 1)
        self.assertEqual(bridge.finalized_requests, [])
        self.assertTrue(pending.kwargs["structured_content"]["pendingIntentReplaceable"])
        self.assertTrue(review.kwargs["structured_content"]["reviewIsReadbackOnly"])
        self.assertEqual(review.kwargs["structured_content"]["reviewedRequests"], [])
        self.assertTrue(final.kwargs["structured_content"]["intentFinalized"])
        self.assertEqual(final.kwargs["structured_content"]["finalizedPendingDigest"], digest)
        self.assertFalse(final.kwargs["structured_content"]["securityAdmissionPerformed"])
        self.assertFalse(final.kwargs["structured_content"]["effectExecuted"])

    def test_finalize_before_readback_is_rejected(self) -> None:
        bridge = self.bridge()
        bridge.execute(self.pending_call(), step_id="step:1")
        with self.assertRaises(self.FakeError) as raised:
            bridge.execute(self.finalize_call(1, "sha256:" + "0" * 64), step_id="step:2")
        self.assertIn("not been read back", str(raised.exception))
        self.assertFalse(bridge.finalized)

    def test_stale_review_revision_is_rejected(self) -> None:
        bridge = self.bridge()
        bridge.execute(self.pending_call(), step_id="step:1")
        bridge.execute(self.pending_call(), step_id="step:2")
        with self.assertRaises(self.FakeError) as raised:
            bridge.execute(self.review_call(1), step_id="step:3")
        self.assertIn("stale", str(raised.exception).lower())
        self.assertEqual(bridge.review_count, 0)

    def test_revision_after_readback_invalidates_old_readback(self) -> None:
        bridge = self.bridge()
        bridge.execute(self.pending_call(), step_id="step:1")
        review = bridge.execute(self.review_call(1), step_id="step:2")
        digest = review.kwargs["structured_content"]["reviewedPendingDigest"]
        bridge.execute(self.pending_call(), step_id="step:3")
        self.assertIsNone(bridge.reviewed_revision)
        self.assertIsNone(bridge.reviewed_digest)
        with self.assertRaises(self.FakeError) as raised:
            bridge.execute(self.finalize_call(2, digest), step_id="step:4")
        self.assertIn("not been read back", str(raised.exception))

    def test_finalize_digest_must_match_exact_readback(self) -> None:
        bridge = self.bridge()
        bridge.execute(self.pending_call(), step_id="step:1")
        bridge.execute(self.review_call(1), step_id="step:2")
        with self.assertRaises(self.FakeError) as raised:
            bridge.execute(self.finalize_call(1, "sha256:" + "f" * 64), step_id="step:3")
        self.assertIn("does not match", str(raised.exception))
        self.assertFalse(bridge.finalized)

    def test_pending_cannot_change_after_finalization(self) -> None:
        bridge = self.bridge()
        bridge.execute(self.pending_call(), step_id="step:1")
        review = bridge.execute(self.review_call(1), step_id="step:2")
        digest = review.kwargs["structured_content"]["reviewedPendingDigest"]
        bridge.execute(self.finalize_call(1, digest), step_id="step:3")
        with self.assertRaises(self.FakeError) as raised:
            bridge.execute(self.pending_call(), step_id="step:4")
        self.assertIn("finalized", str(raised.exception).lower())

    def test_security_decision_requires_candidate_conclusion_and_tool_finalization(self) -> None:
        self.assertFalse(
            _can_materialize_security_decision(
                stop_code="candidate_completed", conclusion_present=True, intent_finalized=False
            )
        )
        self.assertFalse(
            _can_materialize_security_decision(
                stop_code="needs_input", conclusion_present=True, intent_finalized=True
            )
        )
        self.assertTrue(
            _can_materialize_security_decision(
                stop_code="candidate_completed", conclusion_present=True, intent_finalized=True
            )
        )


if __name__ == "__main__":
    unittest.main()
