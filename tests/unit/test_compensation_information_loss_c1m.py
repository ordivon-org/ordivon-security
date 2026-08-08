from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security.cli_compensation_information_loss_acceptance import (
    _initialize_private_world,
    _sender_ledger,
    _successor_view,
    apply_idempotent_private_compensation,
    apply_naive_private_compensation,
    classify_successor_view,
)


class CompensationInformationLossC1MTests(unittest.TestCase):
    def test_successor_view_without_private_truth_classifies_unknown(self) -> None:
        view = _successor_view(_sender_ledger())
        result = classify_successor_view(view)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["blindCompensationAuthorized"])

    def test_naive_compensation_is_not_retry_safe(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "private"
            setup = _initialize_private_world(root)
            self.assertEqual(setup["afterSecondOriginal"], 2)
            self.assertEqual(apply_naive_private_compensation(root)["privateBalanceAfter"], 1)
            self.assertEqual(apply_naive_private_compensation(root)["privateBalanceAfter"], 0)

    def test_idempotent_compensator_converges_after_replay(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "private"
            _initialize_private_world(root)
            first = apply_idempotent_private_compensation(root)
            second = apply_idempotent_private_compensation(root)
            self.assertEqual(first["status"], "applied")
            self.assertEqual(second["status"], "already-repaired")
            self.assertFalse(second["worldMutated"])
            self.assertEqual(second["privateBalanceAfter"], 1)

    def test_idempotent_compensator_fails_closed_outside_contract(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "private"
            root.mkdir(parents=True)
            from ordivon_security.cli_compensation_information_loss_acceptance import (
                _set_private_balance,
            )

            _set_private_balance(root, 0)
            result = apply_idempotent_private_compensation(root)
            self.assertEqual(result["status"], "conflict")
            self.assertEqual(result["privateBalanceAfter"], 0)


if __name__ == "__main__":
    unittest.main()
