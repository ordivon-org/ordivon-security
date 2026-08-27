from __future__ import annotations

import unittest

from ordivon_security.cli_p1_capability_surface_transfer import (
    _compiled_interfaces,
    _context,
    run_fault_injection,
)
from ordivon_security.cli_p1_physical_adaptation import _VARIANTS, _PhysicalWorld


class P1CapabilitySurfaceTransferTests(unittest.TestCase):
    def _observation(self, variant_id: str):
        variant = next(item for item in _VARIANTS if item.variant_id == variant_id)
        world = _PhysicalWorld(variant)
        try:
            return world.observation()
        finally:
            self.assertTrue(world.close())

    def test_all_unknown_exposes_only_inspection(self) -> None:
        obs = self._observation("all-control-unknown")
        self.assertEqual(
            [item.capability for item in _compiled_interfaces(obs)],
            ["inspect.applicability"],
        )

    def test_revoked_credential_is_withdrawn_but_current_script_and_maintenance_remain(self) -> None:
        obs = self._observation("script-current-credential-revoked")
        self.assertEqual(
            [item.capability for item in _compiled_interfaces(obs)],
            ["control.script", "control.maintenance", "inspect.applicability"],
        )

    def test_compiler_does_not_use_hidden_counterplay_truth(self) -> None:
        obs = self._observation("stale-credential-counterplay")
        self.assertEqual(len(_compiled_interfaces(obs)), 4)

    def test_compiled_context_differs_only_in_effect_interface_set(self) -> None:
        obs = self._observation("all-control-unknown")
        source, compiled = _context(observation=obs, compiled=True, turn=0)
        a = source.to_dict()
        b = compiled.to_dict()
        self.assertNotEqual(a["effectInterfaces"], b["effectInterfaces"])
        a.pop("effectInterfaces")
        b.pop("effectInterfaces")
        self.assertEqual(a, b)

    def test_fault_injection_proves_unknown_success_does_not_bypass_current_surface_gate(self) -> None:
        result = run_fault_injection()
        self.assertTrue(all(result["gates"].values()))
        unknown = result["cases"][0]
        self.assertEqual(unknown["rawStaticSurface"]["currentVisibleStatusAtDecision"], "UNKNOWN")
        self.assertTrue(unknown["rawStaticSurface"]["event"]["verifiedConsequence"]["controlEstablished"])
        self.assertTrue(unknown["currentCompiledSurface"]["decisionRejectedBeforeWorldEffect"])
        self.assertFalse(unknown["currentCompiledSurface"]["providerAttempted"])


if __name__ == "__main__":
    unittest.main()
