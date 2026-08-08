from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ordivon_security.range.windows_fabric_reconcile import (
    _remove_host_links,
    reconcile_windows_fabric_range_runs,
)
from ordivon_security.range.windows_fabric_recovery_ownership import (
    acquire_windows_fabric_successor_claim,
)


class WindowsFabricRangeReconcileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "runs").mkdir()
        (self.root / "run-ledgers").mkdir()
        (self.root / "canaries").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _s6_ledger(
        self, *, session_id: str = "range-session:s6-recovery-test"
    ) -> tuple[Path, Path]:
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
        run_token = f"s6-{token}"
        run_path = self.root / "runs" / run_token
        run_path.mkdir()
        for name in (
            "system-overlay.qcow2",
            "OVMF_VARS.4m.fd",
            "ordivon-run.img",
            "qmp.sock",
            "swtpm.sock",
        ):
            (run_path / name).touch()
        (run_path / "tpm-state").mkdir()
        canary = self.root / "canaries" / f"ordivon-s6-{token}.exe"
        canary.write_bytes(b"canary")
        namespaces = [f"s6f{token}", f"s6p{token}", f"s6q{token}"]
        host_links = [f"q{token}", f"w{token}"]
        ledger = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run-state",
            "providerId": "provider:windows-kvm",
            "instanceId": f"range-instance:{run_token}",
            "generation": "windows-kvm:test",
            "phase": "executing",
            "ownerPid": 999999,
            "ownerStartTime": 1,
            "runPath": str(run_path),
            "overlayPath": str(run_path / "system-overlay.qcow2"),
            "varsPath": str(run_path / "OVMF_VARS.4m.fd"),
            "qmpPath": str(run_path / "qmp.sock"),
            "tpmSocketPath": str(run_path / "swtpm.sock"),
            "tpmStatePath": str(run_path / "tpm-state"),
            "qemuPid": 0,
            "qemuStartTime": None,
            "swtpmPid": 0,
            "swtpmStartTime": None,
            "peerPid": 0,
            "peerStartTime": None,
            "capturePid": 0,
            "captureStartTime": None,
            "networkMode": "isolated-l2-no-uplink",
            "rangeSessionId": session_id,
            "rangeId": "range:windows-topology-churn-s6",
            "fabricNamespace": namespaces[0],
            "peerNamespace": namespaces[2],
            "ownedNamespaceCandidates": namespaces,
            "ownedHostLinkCandidates": host_links,
            "topologyPhase": "peer-b-present",
            "currentPeerAddress": "10.253.70.4",
            "canaryPath": str(canary),
            "canaryDigest": "sha256:" + "1" * 64,
        }
        ledger_path = self.root / "run-ledgers" / f"{run_token}.json"
        ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
        return ledger_path, canary

    def test_reconciles_exact_orphan_range_identity_and_leaves_zero_declared_residuals(
        self,
    ) -> None:
        ledger_path, canary = self._s6_ledger()
        ledger = json.loads(ledger_path.read_text())
        run_path = Path(ledger["runPath"])
        namespaces = tuple(ledger["ownedNamespaceCandidates"])
        with (
            patch(
                "ordivon_security.range.windows_fabric_reconcile._remove_namespaces",
                return_value=(list(namespaces), []),
            ),
            patch(
                "ordivon_security.range.windows_fabric_reconcile._terminate_from_ledger",
                return_value=True,
            ),
            patch(
                "ordivon_security.range.windows_fabric_reconcile._remove_host_links",
                return_value=(list(ledger["ownedHostLinkCandidates"]), []),
            ),
            patch(
                "ordivon_security.range.windows_fabric_reconcile._root_link_kinds",
                return_value={},
            ),
        ):
            result = reconcile_windows_fabric_range_runs(self.root)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["reconciled"], 1)
        self.assertFalse(run_path.exists())
        self.assertFalse(ledger_path.exists())
        self.assertFalse(canary.exists())
        item = result["results"][0]
        self.assertEqual(item["topologyPhase"], "peer-b-present")
        self.assertEqual(item["residualNamespaces"], [])
        self.assertEqual(item["residualHostLinks"], [])

    def test_final_reconciliation_preserves_then_clears_successor_claim_history(self) -> None:
        ledger_path, canary = self._s6_ledger()
        ledger = json.loads(ledger_path.read_text())
        run_path = Path(ledger["runPath"])
        namespaces = tuple(ledger["ownedNamespaceCandidates"])
        first = acquire_windows_fabric_successor_claim(
            self.root,
            ledger_path=ledger_path,
            expected_ledger_digest="sha256:" + hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
            purpose="unit-test-first",
        )
        self.assertIsNotNone(first)
        assert first is not None
        first_id = first.claim["claimId"]
        first.release(disposition="released-first")
        ledger["updatedAtNs"] = 2
        ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
        second = acquire_windows_fabric_successor_claim(
            self.root,
            ledger_path=ledger_path,
            expected_ledger_digest="sha256:" + hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
            purpose="unit-test-second",
        )
        self.assertIsNotNone(second)
        assert second is not None
        second_id = second.claim["claimId"]
        second.release(disposition="released-second")
        with (
            patch(
                "ordivon_security.range.windows_fabric_reconcile._remove_namespaces",
                return_value=(list(namespaces), []),
            ),
            patch(
                "ordivon_security.range.windows_fabric_reconcile._terminate_from_ledger",
                return_value=True,
            ),
            patch(
                "ordivon_security.range.windows_fabric_reconcile._remove_host_links",
                return_value=(list(ledger["ownedHostLinkCandidates"]), []),
            ),
            patch(
                "ordivon_security.range.windows_fabric_reconcile._root_link_kinds",
                return_value={},
            ),
        ):
            result = reconcile_windows_fabric_range_runs(self.root)
        item = result["results"][0]
        self.assertEqual(item["successorClaimObserved"]["claimId"], second_id)
        self.assertEqual(
            [claim["claimId"] for claim in item["successorClaimHistoryObserved"]],
            [first_id],
        )
        self.assertFalse((self.root / "recovery-claims" / "s6-12345678.json").exists())
        self.assertFalse((self.root / "recovery-claims" / "history" / "s6-12345678").exists())
        self.assertFalse(run_path.exists())
        self.assertFalse(ledger_path.exists())
        self.assertFalse(canary.exists())

    def test_active_exact_owner_is_skipped(self) -> None:
        ledger_path, _ = self._s6_ledger()
        with patch(
            "ordivon_security.range.windows_fabric_reconcile._identity_alive",
            return_value=True,
        ):
            result = reconcile_windows_fabric_range_runs(self.root)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["skippedActive"], 1)
        self.assertTrue(ledger_path.exists())

    def test_live_successor_claim_blocks_orphan_reconciliation(self) -> None:
        ledger_path, _ = self._s6_ledger()
        digest = "sha256:" + hashlib.sha256(ledger_path.read_bytes()).hexdigest()
        claim = acquire_windows_fabric_successor_claim(
            self.root,
            ledger_path=ledger_path,
            expected_ledger_digest=digest,
            purpose="unit-test-successor",
        )
        self.assertIsNotNone(claim)
        assert claim is not None
        try:
            result = reconcile_windows_fabric_range_runs(self.root)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["reconciled"], 0)
            self.assertEqual(result["skippedSuccessorActive"], 1)
            self.assertEqual(result["results"][0]["decision"], "skipped-successor-active")
            self.assertTrue(ledger_path.exists())
        finally:
            claim.release()

    def test_tampered_namespace_candidates_are_attention_required_not_deleted(self) -> None:
        ledger_path, _ = self._s6_ledger()
        ledger = json.loads(ledger_path.read_text())
        ledger["ownedNamespaceCandidates"][-1] = "default"
        ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
        with patch("ordivon_security.range.windows_fabric_reconcile._remove_namespaces") as remove:
            result = reconcile_windows_fabric_range_runs(self.root)
        self.assertEqual(result["status"], "attention-required")
        self.assertEqual(result["attentionRequired"], 1)
        remove.assert_not_called()
        self.assertTrue(ledger_path.exists())

    def test_tampered_host_link_candidates_are_attention_required_not_deleted(self) -> None:
        ledger_path, _ = self._s6_ledger()
        ledger = json.loads(ledger_path.read_text())
        ledger["ownedHostLinkCandidates"][-1] = "eth0"
        ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
        with patch("ordivon_security.range.windows_fabric_reconcile._remove_host_links") as remove:
            result = reconcile_windows_fabric_range_runs(self.root)
        self.assertEqual(result["status"], "attention-required")
        self.assertEqual(result["attentionRequired"], 1)
        remove.assert_not_called()
        self.assertTrue(ledger_path.exists())

    def test_host_link_cleanup_refuses_non_veth_name_collision(self) -> None:
        names = ("q12345678", "w12345678")
        with (
            patch(
                "ordivon_security.range.windows_fabric_reconcile._root_link_kinds",
                return_value={"q12345678": "bridge"},
            ),
            patch("ordivon_security.range.windows_fabric_reconcile.subprocess.run") as run,
        ):
            requested, residual = _remove_host_links(Path("/usr/bin/ip"), names)
        self.assertEqual(requested, [])
        self.assertEqual(residual, ["q12345678"])
        run.assert_not_called()

    def test_evaluation_ledger_is_outside_range_reconciler_authority(self) -> None:
        path = self.root / "run-ledgers" / "evaluation.json"
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-kvm-run-state",
                    "providerId": "provider:windows-kvm",
                    "instanceId": "evaluation-instance:test",
                }
            ),
            encoding="utf-8",
        )
        result = reconcile_windows_fabric_range_runs(self.root)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["reconciled"], 0)
        self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
