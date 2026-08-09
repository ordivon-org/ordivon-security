from __future__ import annotations

import unittest

from ordivon_security.cli_intent_readback_if1_acceptance import _EXPECTED_CONTEXT_DIGEST
from ordivon_security.cli_intent_finalization_if0_acceptance import _exact_ac2_mismatch_context


class IntentReadbackIF1AcceptanceTests(unittest.TestCase):
    def test_replays_exact_ac2_mismatch_context(self) -> None:
        context = _exact_ac2_mismatch_context()
        self.assertEqual(context.digest, _EXPECTED_CONTEXT_DIGEST)
        self.assertEqual(context.visible_observation["privateSignal"]["value"], 0)
        self.assertEqual(context.visible_observation["verifiedDisclosureForActor"]["value"], 1)


if __name__ == "__main__":
    unittest.main()
