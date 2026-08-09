from __future__ import annotations

import unittest

from ordivon_security.integrations.harness_finalized_range_intent import (
    _FinalizedRangeIntentBridge,
)


class FinalizedRangeIntentIF0Tests(unittest.TestCase):
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
            bridge_identity={"kind": "test-if0"},
            tool_bridge_error_type=self.FakeError,
            model_correctable_kind="model_correctable",
        )

    def test_pending_revision_then_finalize_exact_revision(self) -> None:
        class Pending:
            name = "submit_range_intents"
            arguments = {"requests": []}
            tool_call_id = "call:pending"

        class Finalize:
            name = "finalize_range_intent"
            arguments = {"expectedRevision": 1}
            tool_call_id = "call:finalize"

        bridge = self.bridge()
        pending = bridge.execute(Pending(), step_id="step:1")
        final = bridge.execute(Finalize(), step_id="step:2")
        self.assertEqual(bridge.intent_revisions, [[]])
        self.assertEqual(bridge.finalized_revision, 1)
        self.assertEqual(bridge.finalized_requests, [])
        self.assertTrue(pending.kwargs["structured_content"]["pendingIntentReplaceable"])
        self.assertFalse(pending.kwargs["structured_content"]["intentFinalized"])
        self.assertTrue(final.kwargs["structured_content"]["intentFinalized"])
        self.assertFalse(final.kwargs["structured_content"]["securityAdmissionPerformed"])
        self.assertFalse(final.kwargs["structured_content"]["effectExecuted"])

    def test_stale_revision_cannot_be_finalized(self) -> None:
        class Pending:
            name = "submit_range_intents"
            arguments = {"requests": []}
            tool_call_id = "call:pending"

        class StaleFinalize:
            name = "finalize_range_intent"
            arguments = {"expectedRevision": 1}
            tool_call_id = "call:stale"

        bridge = self.bridge()
        bridge.execute(Pending(), step_id="step:1")
        bridge.execute(Pending(), step_id="step:2")
        with self.assertRaises(self.FakeError) as raised:
            bridge.execute(StaleFinalize(), step_id="step:3")
        self.assertEqual(raised.exception.kind, "model_correctable")
        self.assertIn("stale", str(raised.exception).lower())
        self.assertFalse(bridge.finalized)

    def test_pending_cannot_change_after_finalization(self) -> None:
        class Pending:
            name = "submit_range_intents"
            arguments = {"requests": []}
            tool_call_id = "call:pending"

        class Finalize:
            name = "finalize_range_intent"
            arguments = {"expectedRevision": 1}
            tool_call_id = "call:finalize"

        bridge = self.bridge()
        bridge.execute(Pending(), step_id="step:1")
        bridge.execute(Finalize(), step_id="step:2")
        with self.assertRaises(self.FakeError) as raised:
            bridge.execute(Pending(), step_id="step:3")
        self.assertIn("finalized", str(raised.exception).lower())

    def test_finalize_requires_explicit_pending_even_for_zero_effect(self) -> None:
        class Finalize:
            name = "finalize_range_intent"
            arguments = {"expectedRevision": 1}
            tool_call_id = "call:finalize"

        bridge = self.bridge()
        with self.assertRaises(self.FakeError) as raised:
            bridge.execute(Finalize(), step_id="step:1")
        self.assertIn("no pending", str(raised.exception).lower())


if __name__ == "__main__":
    unittest.main()
