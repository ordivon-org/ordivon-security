from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from ordivon_security.range.protocol import RangeSessionInstance
from ordivon_security.range.windows_topology_churn import WindowsTopologyChurnRange
from ordivon_security.windows_kvm_recovery_acceptance_support import ledger_semantic_binding


class C1bAcceptanceTests(unittest.TestCase):
    def test_current_s6_ledger_without_effect_binding_is_semantically_opaque(self) -> None:
        ledger = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run-state",
            "topologyPhase": "peer-a-removed",
            "currentPeerAddress": None,
        }
        self.assertIsNone(ledger_semantic_binding(ledger))

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
        self.assertEqual(ledger_semantic_binding(ledger), binding)

    def test_s6_running_ledger_extra_persists_exact_effect_binding(self) -> None:
        backend = object.__new__(WindowsTopologyChurnRange)
        backend.config = SimpleNamespace(
            canary_path=Path("/tmp/c1b-canary.exe"),
            canary_digest="sha256:" + "4" * 64,
        )
        binding = {
            "requestId": "range-effect-request:test",
            "requestDigest": "sha256:" + "1" * 64,
            "admissionDigest": "sha256:" + "2" * 64,
            "authorityId": "range-authority:test",
            "authorityDigest": "sha256:" + "3" * 64,
            "actorId": "actor:test",
            "zoneRef": "zone:s6-fabric",
            "capability": "fabric.peer-replacement",
            "effectType": "fabric.replace-peer-a-with-peer-b",
            "effectId": "range-effect:test",
        }
        receipt = {
            "effectId": "range-effect:test",
            "requestId": "range-effect-request:test",
            "admissionDigest": "sha256:" + "2" * 64,
            "status": "accepted-pending-execution",
            "worldEffectVerified": False,
        }
        run = SimpleNamespace(
            instance=RangeSessionInstance(
                instance_id="range-instance:s6-test",
                session_id="range-session:c1b-test",
            ),
            state={
                "rangeSpecDigest": "sha256:" + "5" * 64,
                "topologyPhase": "peer-a-removed",
                "currentPeerAddress": None,
                "actorReplacementRequest": binding,
                "actorReplacementReceipt": receipt,
            },
        )
        extra = backend._run_ledger_extra(run)
        self.assertEqual(extra["actorReplacementRequest"], binding)
        self.assertEqual(extra["actorReplacementReceipt"], receipt)
        binding["effectId"] = "range-effect:mutated-after-snapshot"
        self.assertEqual(extra["actorReplacementRequest"]["effectId"], "range-effect:test")


if __name__ == "__main__":
    unittest.main()
