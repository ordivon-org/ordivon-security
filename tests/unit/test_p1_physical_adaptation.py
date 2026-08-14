from __future__ import annotations

import unittest

from ordivon_security.cli_p1_physical_adaptation import (
    _VARIANTS,
    _PhysicalWorld,
    _adaptive_policy,
    _run_policy,
    _static_policy,
)


class P1PhysicalAdaptationTests(unittest.TestCase):
    def test_world_is_bounded_owned_and_has_four_frozen_variants(self) -> None:
        self.assertEqual(len(_VARIANTS), 4)
        self.assertTrue(all(v.variant_id for v in _VARIANTS))

    def test_static_fails_counterplay_while_adaptive_substitutes(self) -> None:
        variant = next(v for v in _VARIANTS if v.variant_id == "stale-credential-counterplay")
        static = _run_policy(variant, "static-scripted", _static_policy)
        adaptive = _run_policy(variant, "constrained-adaptive", _adaptive_policy)
        self.assertFalse(static["success"])
        self.assertTrue(adaptive["success"])
        self.assertEqual(
            [d["action"] for d in adaptive["decisions"]],
            ["control.credential", "control.maintenance"],
        )
        self.assertTrue(static["residualClosed"])
        self.assertTrue(adaptive["residualClosed"])

    def test_adaptive_inspects_when_all_consequential_paths_unknown(self) -> None:
        variant = next(v for v in _VARIANTS if v.variant_id == "all-control-unknown")
        adaptive = _run_policy(variant, "constrained-adaptive", _adaptive_policy)
        self.assertTrue(adaptive["success"])
        self.assertEqual(adaptive["decisions"][0]["action"], "inspect.applicability")
        self.assertEqual(adaptive["decisions"][1]["action"], "control.script")

    def test_inspection_does_not_bypass_first_consequential_counterplay(self) -> None:
        variant = next(v for v in _VARIANTS if v.variant_id == "stale-credential-counterplay")
        world = _PhysicalWorld(variant)
        try:
            inspection = world.apply("inspect.applicability")
            self.assertIsNone(inspection["counterplay"])
            credential = world.apply("control.credential")
            self.assertIsNotNone(credential["counterplay"])
            self.assertFalse(credential["verifiedConsequence"]["controlEstablished"])
        finally:
            self.assertTrue(world.close())

    def test_provider_receipt_is_not_world_truth(self) -> None:
        variant = next(v for v in _VARIANTS if v.variant_id == "current-low-cost")
        result = _run_policy(variant, "constrained-adaptive", _adaptive_policy)
        event = result["decisions"][0]["event"]
        self.assertFalse(event["providerReceipt"]["worldTruthVerified"])
        self.assertTrue(event["verifiedConsequence"]["controlEstablished"])


if __name__ == "__main__":
    unittest.main()
