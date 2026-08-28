from __future__ import annotations

import unittest

from ordivon_security.windows_kvm_acceptance_support import (
    topology_guest_claim_passes,
    topology_phases,
)


class WindowsKvmAcceptanceSupportTests(unittest.TestCase):
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
