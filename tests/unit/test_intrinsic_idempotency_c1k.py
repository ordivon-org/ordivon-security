from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security.cli_intrinsic_idempotency_acceptance import (
    _DESIRED_VALUE,
    _target_path,
    ensure_world_target,
    observe_world_target,
)


class IntrinsicIdempotencyC1KTests(unittest.TestCase):
    def test_repeated_ensure_converges_without_second_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            first = ensure_world_target(root)
            second = ensure_world_target(root)
            self.assertEqual(first["status"], "applied")
            self.assertTrue(first["worldMutated"])
            self.assertEqual(second["status"], "already-satisfied")
            self.assertFalse(second["worldMutated"])
            self.assertEqual(observe_world_target(root)["semanticConsequenceCount"], 1)

    def test_same_name_wrong_type_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            root.mkdir()
            _target_path(root).write_text("collision", encoding="utf-8")
            result = ensure_world_target(root)
            self.assertEqual(result["status"], "conflict")
            self.assertFalse(result["worldMutated"])
            self.assertEqual(_target_path(root).read_text(encoding="utf-8"), "collision")

    def test_exact_symlink_value_is_the_consequence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "world"
            ensure_world_target(root)
            self.assertTrue(_target_path(root).is_symlink())
            self.assertEqual(_target_path(root).readlink().as_posix(), _DESIRED_VALUE)


if __name__ == "__main__":
    unittest.main()
