from __future__ import annotations

import unittest

from ordivon_security.windows_kvm_acceptance_support import (
    range_backend_state,
    topology_guest_claim_passes,
    topology_phases,
    world_still_peer_a,
)


class _Session:
    def __init__(self, backend_state: object) -> None:
        self._backend_state = backend_state

    def inspect(self) -> dict[str, object]:
        return {"backendState": self._backend_state}


class WindowsKvmAcceptanceSupportTests(unittest.TestCase):
    def test_range_backend_state_and_peer_a_predicate_preserve_c1_boundary(self) -> None:
        state = {
            "topologyChurnCompleted": False,
            "actorReplacementRequest": None,
            "fabricTruth": {"phase": "peer-a-present", "currentPeerAddress": "10.253.70.3"},
        }
        self.assertIs(range_backend_state(_Session(state)), state)
        self.assertTrue(world_still_peer_a(state))
        changed = {**state, "actorReplacementRequest": {"effectId": "x"}}
        self.assertFalse(world_still_peer_a(changed))
        with self.assertRaisesRegex(RuntimeError, "backend state is unavailable"):
            range_backend_state(_Session(None))

    def test_topology_guest_claim_passes_only_exact_completed_fixture(self) -> None:
        claim = {
            "status": "completed",
            "fixtureResult": {
                "completed": True,
                "configuredStaticIpv4": True,
                "rangeRoutePresent": True,
                "guestNicMac": "52-54-00-53-35-01",
                "peerAConnected": True,
                "peerABannerMatched": True,
                "peerBConnected": True,
                "peerBBannerMatched": True,
                "externalNetworkRequested": False,
            },
        }
        self.assertTrue(topology_guest_claim_passes(claim))
        changed = {**claim, "fixtureResult": {**claim["fixtureResult"], "peerBConnected": False}}
        self.assertFalse(topology_guest_claim_passes(changed))

    def test_topology_phases_reads_only_world_truth_events(self) -> None:
        events = [
            {"eventType": "world.fabric-topology-observed", "payload": {"phase": "peer-a-present"}},
            {"eventType": "management.note", "payload": {"phase": "fake"}},
            {"eventType": "world.fabric-topology-observed", "payload": {"phase": "peer-b-present"}},
        ]
        self.assertEqual(topology_phases(events), {"peer-a-present", "peer-b-present"})


if __name__ == "__main__":
    unittest.main()
