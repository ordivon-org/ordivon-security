from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ordivon_security.range.windows_fabric_reconcile import (
    reconcile_windows_fabric_range_runs,
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

    def test_tampered_namespace_candidates_are_attention_required_not_deleted(self) -> None:
        ledger_path, _ = self._s6_ledger()
        ledger = json.loads(ledger_path.read_text())
        ledger["ownedNamespaceCandidates"][-1] = "default"
        ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
        with patch(
            "ordivon_security.range.windows_fabric_reconcile._remove_namespaces"
        ) as remove:
            result = reconcile_windows_fabric_range_runs(self.root)
        self.assertEqual(result["status"], "attention-required")
        self.assertEqual(result["attentionRequired"], 1)
        remove.assert_not_called()
        self.assertTrue(ledger_path.exists())

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
