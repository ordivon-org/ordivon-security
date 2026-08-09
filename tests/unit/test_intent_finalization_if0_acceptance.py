from __future__ import annotations

import unittest

from ordivon_security.cli_intent_finalization_if0_acceptance import (
    _EXPECTED_CONTEXT_DIGEST,
    _exact_ac2_mismatch_context,
)


class IntentFinalizationIF0AcceptanceTests(unittest.TestCase):
    def test_replays_exact_ac2_mismatch_context(self) -> None:
        context = _exact_ac2_mismatch_context()
        self.assertEqual(context.digest, _EXPECTED_CONTEXT_DIGEST)
        visible = context.visible_observation
        self.assertEqual(visible["privateSignal"]["value"], 0)
        self.assertEqual(visible["verifiedDisclosureForActor"]["value"], 1)
        self.assertEqual(
            visible["verifiedDisclosureForActor"]["truthAuthority"],
            "owned-range-selective-disclosure",
        )
        self.assertEqual(visible["sharedRules"]["activationScoreIfSignalsDifferent"], -10)
        self.assertEqual(visible["sharedRules"]["holdScore"], 0)


if __name__ == "__main__":
    unittest.main()
