from __future__ import annotations

import contextlib
import io
import json
import unittest

import ordivon_security
from ordivon_security.cli_surface import main as surface_cli_main
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
        names = {entry["name"] for entry in value["entries"]}
        self.assertIn("ResearchCorpus", names)
        self.assertIn("CA-LIC entitlement authority research", names)

    def test_surface_cli_projects_manifest_without_experiment(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = surface_cli_main([])
        self.assertEqual(status, 0)
        value = json.loads(stdout.getvalue())
        self.assertEqual(value, ordivon_security.security_surface_manifest())
        self.assertEqual(value["kind"], "ordivon.security.agent-first-surface")

    def test_canonical_integration_imports_are_available(self) -> None:
        self.assertTrue(HostAssignedDeepSeekHarnessTurnDriver.__name__)
        self.assertTrue(RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver.__name__)

    def test_canonical_world_boundary_imports_are_available(self) -> None:
        self.assertTrue(WorldMessageInbox.__name__)
        self.assertTrue(WorldResourceInbox.__name__)
        self.assertTrue(WorldEntityKvmDestination.__name__)


class OrdinarySecuritySurfaceTests(unittest.TestCase):
    def test_ordinary_view_is_derived_and_excludes_research_apparatus(self) -> None:
        ordinary = ordivon_security.security_ordinary_surface_manifest()
        self.assertEqual(ordinary["kind"], "ordivon.security-ordinary-surface")
        names = {entry["name"] for entry in ordinary["surfaceEntries"]}
        self.assertEqual(
            names,
            {"EvidenceRecorder", "RangeSession", "ResearchCorpus", "Software Evaluation"},
        )
        self.assertNotIn("Acceptance runners", names)
        self.assertNotIn("CA-LIC entitlement authority research", names)
        routes = {route["job"]: route["primarySurface"] for route in ordinary["routes"]}
        self.assertEqual(routes["provider-snapshot-currentness"], "ResearchCorpus")
        self.assertEqual(routes["software-or-endpoint-evaluation"], "Software Evaluation")

    def test_ordinary_view_does_not_grant_authority(self) -> None:
        ordinary = ordivon_security.security_ordinary_surface_manifest()
        self.assertIn("does not grant execution", ordinary["authorityBoundary"].lower())
        self.assertIn("reproduction/provenance", ordinary["researchBoundary"])


if __name__ == "__main__":
    unittest.main()
