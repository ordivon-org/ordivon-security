from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security.cli_compensation_acceptance import (
    _initialize_world,
    apply_guarded_compensation,
    apply_naive_compensation,
    apply_original_effect,
    classify_compensation_recovery,
    observe_balance,
)


class CompensationC1LTests(unittest.TestCase):
    def test_original_effect_is_non_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            _initialize_world(root)
            apply_original_effect(root)
            apply_original_effect(root)
            self.assertEqual(observe_balance(root)["balance"], 2)

    def test_naive_compensation_is_not_retry_safe(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            _initialize_world(root)
            apply_original_effect(root)
            apply_original_effect(root)
            apply_naive_compensation(root)
            apply_naive_compensation(root)
            self.assertEqual(observe_balance(root)["balance"], 0)

    def test_guarded_compensation_repairs_only_exact_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            _initialize_world(root)
            apply_original_effect(root)
            apply_original_effect(root)
            first = apply_guarded_compensation(root)
            second = apply_guarded_compensation(root)
            self.assertEqual(first["status"], "applied")
            self.assertEqual(second["status"], "already-repaired")
            self.assertEqual(observe_balance(root)["balance"], 1)

    def test_guarded_compensation_does_not_execute_original_effect_from_zero(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            _initialize_world(root)
            self.assertEqual(
                classify_compensation_recovery(root)["status"], "unexpected-world-state"
            )
            result = apply_guarded_compensation(root)
            self.assertEqual(result["status"], "conflict")
            self.assertEqual(observe_balance(root)["balance"], 0)


if __name__ == "__main__":
    unittest.main()
