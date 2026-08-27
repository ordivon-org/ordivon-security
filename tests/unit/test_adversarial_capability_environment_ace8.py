from __future__ import annotations

import unittest
from pathlib import Path

from ordivon_security.integrations import DeepSeekRangeIntentConfig


class AdversarialCapabilityEnvironmentAce8Tests(unittest.TestCase):
    def test_consumer_representation_contract_mode_is_opt_in(self) -> None:
        base = DeepSeekRangeIntentConfig(secret_path=Path("/tmp/test.json"))
        aware = DeepSeekRangeIntentConfig(
            secret_path=Path("/tmp/test.json"), consume_representation_contract=True
        )
        self.assertFalse(base.consume_representation_contract)
        self.assertTrue(aware.consume_representation_contract)

    def test_driver_source_binds_prompt_revision_to_consumer_mode(self) -> None:
        source = Path("src/ordivon_security/integrations/harness_range_intent.py").read_text()
        self.assertIn('"-representation-contract-v1"', source)
        self.assertIn("decisionAuthoritativeField=consequence", source)
        self.assertIn("conflictDisposition=consequence-governs", source)
        self.assertIn("semantics is descriptive and non-authoritative", source)


if __name__ == "__main__":
    unittest.main()
