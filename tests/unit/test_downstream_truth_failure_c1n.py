from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security.cli_downstream_truth_failure_acceptance import (
    _fault_truth,
    _seal_witness,
    _write_balance,
    apply_ensure_repaired,
    inspect_authority_truth,
    restore_truth_from_witness,
)


class DownstreamTruthFailureC1NTests(unittest.TestCase):
    def test_missing_truth_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "private"
            _write_balance(root, 2)
            _fault_truth(root, "missing")
            result = apply_ensure_repaired(root)
            self.assertEqual(result["status"], "truth-unavailable")
            self.assertFalse(result["worldMutated"])
            self.assertEqual(result["treeDigestBefore"], result["treeDigestAfter"])

    def test_corrupt_truth_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "private"
            _write_balance(root, 1)
            _fault_truth(root, "corrupt")
            self.assertEqual(inspect_authority_truth(root)["status"], "corrupt")
            self.assertFalse(apply_ensure_repaired(root)["worldMutated"])

    def test_fork_truth_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "private"
            _write_balance(root, 2)
            _fault_truth(root, "fork")
            result = inspect_authority_truth(root)
            self.assertEqual(result["status"], "fork-conflict")
            self.assertFalse(apply_ensure_repaired(root)["worldMutated"])

    def test_verified_witness_restores_then_repairs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "private"
            witness = base / "witness.json"
            _write_balance(root, 2)
            _seal_witness(witness, balance=2, lineage="lineage:test")
            _fault_truth(root, "missing")
            restored = restore_truth_from_witness(root, witness, lineage="lineage:test")
            self.assertEqual(restored["status"], "restored")
            repaired = apply_ensure_repaired(root)
            self.assertEqual(repaired["status"], "applied")
            self.assertEqual(inspect_authority_truth(root)["balance"], 1)


if __name__ == "__main__":
    unittest.main()
