from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from ordivon_security.providers.windows_kvm import _process_start_time
from ordivon_security.range.windows_fabric_recovery_ownership import (
    RecoveryClaimStaleError,
    acquire_windows_fabric_successor_claim,
    try_acquire_windows_fabric_recovery_gate,
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsFabricRecoveryOwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "run-ledgers").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _ledger(self, *, owner_pid: int = 999999, owner_start: int = 1) -> Path:
        path = self.root / "run-ledgers" / "s6-12345678.json"
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-kvm-run-state",
                    "rangeSessionId": "range-session:test",
                    "rangeId": "range:windows-topology-churn-s6",
                    "ownerPid": owner_pid,
                    "ownerStartTime": owner_start,
                    "actorReplacementRequest": {"effectId": "range-effect:test"},
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return path

    def test_successor_claim_excludes_second_recovery_authority_until_release(self) -> None:
        ledger = self._ledger()
        claim = acquire_windows_fabric_successor_claim(
            self.root,
            ledger_path=ledger,
            expected_ledger_digest=_digest(ledger),
            purpose="unit-test-continuation",
        )
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim.claim["state"], "held")
        self.assertEqual(claim.claim["predecessorOwnerPid"], 999999)
        self.assertIsNone(
            try_acquire_windows_fabric_recovery_gate(
                self.root,
                run_token="s6-12345678",
            )
        )
        claim.release()
        gate = try_acquire_windows_fabric_recovery_gate(
            self.root,
            run_token="s6-12345678",
        )
        self.assertIsNotNone(gate)
        assert gate is not None
        gate.release()
        metadata = json.loads((self.root / "recovery-claims" / "s6-12345678.json").read_text())
        self.assertEqual(metadata["state"], "released")
        self.assertIn("releasedAtNs", metadata)

    def test_successor_claim_is_exact_ledger_generation_cas(self) -> None:
        ledger = self._ledger()
        with self.assertRaises(RecoveryClaimStaleError):
            acquire_windows_fabric_successor_claim(
                self.root,
                ledger_path=ledger,
                expected_ledger_digest="sha256:" + "0" * 64,
                purpose="unit-test-stale-generation",
            )
        gate = try_acquire_windows_fabric_recovery_gate(
            self.root,
            run_token="s6-12345678",
        )
        self.assertIsNotNone(gate)
        assert gate is not None
        gate.release()

    def test_successor_claim_refuses_live_predecessor(self) -> None:
        start = _process_start_time(os.getpid())
        assert start is not None
        ledger = self._ledger(owner_pid=os.getpid(), owner_start=start)
        with self.assertRaisesRegex(RuntimeError, "original owner is still alive"):
            acquire_windows_fabric_successor_claim(
                self.root,
                ledger_path=ledger,
                expected_ledger_digest=_digest(ledger),
                purpose="unit-test-live-owner",
            )


if __name__ == "__main__":
    unittest.main()
