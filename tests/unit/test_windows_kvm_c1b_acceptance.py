from __future__ import annotations

import unittest

from ordivon_security.cli_windows_kvm_c1b_acceptance import _ledger_semantic_binding


class C1bAcceptanceTests(unittest.TestCase):
    def test_current_s6_ledger_without_effect_binding_is_semantically_opaque(self) -> None:
        ledger = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run-state",
            "topologyPhase": "peer-a-removed",
            "currentPeerAddress": None,
        }
        self.assertIsNone(_ledger_semantic_binding(ledger))

    def test_effect_binding_is_recognized_without_interpreting_world_truth(self) -> None:
        binding = {
            "requestId": "range-effect-request:test",
            "requestDigest": "sha256:" + "1" * 64,
            "admissionDigest": "sha256:" + "2" * 64,
            "effectId": "range-effect:test",
        }
        ledger = {
            "topologyPhase": "peer-b-present",
            "currentPeerAddress": "10.253.70.4",
            "actorReplacementRequest": binding,
        }
        self.assertEqual(_ledger_semantic_binding(ledger), binding)


if __name__ == "__main__":
    unittest.main()
