from __future__ import annotations

import unittest

from ordivon_security.cli_ca6_tactical_adaptation import (
    _ACTIONS,
    _VARIANTS,
    _World,
    _adaptive_policy,
    _run_policy,
    _static_policy,
)


class Ca6TacticalAdaptationTests(unittest.TestCase):
    def test_arena_has_four_bounded_capabilities_and_four_variants(self) -> None:
        self.assertEqual(
            _ACTIONS,
            (
                "control.credential",
                "control.script",
                "control.exploit",
                "inspect.applicability",
            ),
        )
        self.assertEqual(len(_VARIANTS), 4)

    def test_adaptive_policy_uses_properties_not_variant_identity(self) -> None:
        source_names = _adaptive_policy.__code__.co_names
        self.assertNotIn("variant_id", source_names)
        all_unknown = next(item for item in _VARIANTS if item.variant_id == "all-control-unknown")
        self.assertEqual(_adaptive_policy(_World(all_unknown), 0), "inspect.applicability")

    def test_dynamic_counterplay_requires_current_observation_replan(self) -> None:
        variant = next(item for item in _VARIANTS if item.variant_id == "adaptive-counterplay")
        static = _run_policy(variant, "static-scripted", _static_policy)
        adaptive = _run_policy(variant, "constrained-adaptive", _adaptive_policy)
        self.assertFalse(static["success"])
        self.assertTrue(adaptive["success"])
        self.assertEqual(
            [item["action"] for item in adaptive["decisions"]],
            ["control.credential", "control.exploit"],
        )

    def test_all_unknown_requires_inspection_then_current_applicable_path(self) -> None:
        variant = next(item for item in _VARIANTS if item.variant_id == "all-control-unknown")
        adaptive = _run_policy(variant, "constrained-adaptive", _adaptive_policy)
        self.assertTrue(adaptive["success"])
        self.assertEqual(
            [item["action"] for item in adaptive["decisions"]],
            ["inspect.applicability", "control.exploit"],
        )


if __name__ == "__main__":
    unittest.main()
