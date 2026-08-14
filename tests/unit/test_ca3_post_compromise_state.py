from __future__ import annotations

import unittest
from importlib.resources import files
from pathlib import Path

from ordivon_security.cli_ca3_post_compromise_state import _NODES, _TOKENS


class Ca3PostCompromiseStateTests(unittest.TestCase):
    def test_world_is_bounded_to_three_owned_nodes_and_synthetic_tokens(self) -> None:
        self.assertEqual(_NODES, ("a", "b", "c"))
        self.assertEqual(set(_TOKENS), {"a", "b", "c"})
        self.assertTrue(all(value.startswith("ca3-token-") for value in _TOKENS.values()))

    def test_runner_keeps_persistence_authority_control_and_propagation_distinct(self) -> None:
        path = Path(str(files("ordivon_security").joinpath("cli_ca3_post_compromise_state.py")))
        source = path.read_text(encoding="utf-8")
        self.assertIn("persistencePresent", source)
        self.assertIn("credentialRevoked", source)
        self.assertIn("currentControl", source)
        self.assertIn("delegate-once", source)
        self.assertIn("maxChildren", source)
        self.assertIn("staleBeliefActionsFailAfterEradication", source)
        self.assertNotIn("socket.", source)
        self.assertNotIn("http://", source)
        self.assertNotIn("https://", source)

    def test_no_credential_collection_or_unbounded_propagation_claim(self) -> None:
        path = Path(str(files("ordivon_security").joinpath("cli_ca3_post_compromise_state.py")))
        source = path.read_text(encoding="utf-8")
        self.assertIn("syntheticCredentialsOnly", source)
        self.assertIn("delegationMaxChildren", source)
        self.assertIn("no credential stealing", source)
        self.assertNotIn("RangeActionGateway", source)


if __name__ == "__main__":
    unittest.main()
