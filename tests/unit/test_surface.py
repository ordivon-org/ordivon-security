from __future__ import annotations

import unittest

import ordivon_security
from ordivon_security.integrations import (
    HostAssignedDeepSeekHarnessTurnDriver,
    RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver,
)
from ordivon_security.world_boundary import (
    WorldEntityKvmDestination,
    WorldMessageInbox,
    WorldResourceInbox,
)


class SecuritySurfaceTests(unittest.TestCase):
    def test_manifest_exposes_distinct_maturity_tiers(self) -> None:
        value = ordivon_security.security_surface_manifest()
        tiers = {entry["tier"] for entry in value["entries"]}
        self.assertEqual(
            tiers,
            {"constitution", "profile", "integration", "research-apparatus"},
        )
        self.assertEqual(value["compatibilityFacade"]["maturity"], "mixed")

    def test_canonical_integration_imports_are_available(self) -> None:
        self.assertTrue(HostAssignedDeepSeekHarnessTurnDriver.__name__)
        self.assertTrue(RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver.__name__)

    def test_canonical_world_boundary_imports_are_available(self) -> None:
        self.assertTrue(WorldMessageInbox.__name__)
        self.assertTrue(WorldResourceInbox.__name__)
        self.assertTrue(WorldEntityKvmDestination.__name__)


if __name__ == "__main__":
    unittest.main()
