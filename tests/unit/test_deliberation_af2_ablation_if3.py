from __future__ import annotations

import unittest

from ordivon_security.cli_deliberation_af2_ablation_if3_acceptance import _EXPECTED_CONTEXT_DIGEST
from ordivon_security.cli_intent_finalization_if0_acceptance import _exact_ac2_mismatch_context


class DeliberationAF2AblationIF3Tests(unittest.TestCase):
    def test_exact_context_is_unchanged_ac2_mismatch(self) -> None:
        context = _exact_ac2_mismatch_context()
        self.assertEqual(context.digest, _EXPECTED_CONTEXT_DIGEST)
        self.assertEqual(context.visible_observation["privateSignal"]["value"], 0)
        self.assertEqual(context.visible_observation["verifiedDisclosureForActor"]["value"], 1)
        self.assertEqual(context.visible_observation["sharedRules"]["activationScoreIfSignalsDifferent"], -10)
        self.assertEqual(context.visible_observation["sharedRules"]["holdScore"], 0)


if __name__ == "__main__":
    unittest.main()
