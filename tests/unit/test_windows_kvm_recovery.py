from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import JsonObject
from ordivon_security.evaluation.windows_kvm import (
    _process_start_time,
    _replace_private_json,
)
from ordivon_security.evaluation.windows_kvm_reconcile import (
    _reconcile_benign_fixtures,
    reconcile_windows_kvm_runs,
)


class WindowsKvmRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        (self.state / "runs").mkdir(parents=True)
        (self.state / "run-ledgers").mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _ledger(
        self,
        run_path: Path,
        *,
        owner_pid: int = 0,
        owner_start: int = 0,
        qemu_pid: int = 0,
        qemu_start: int | None = None,
    ) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run-state",
            "providerId": "provider:windows-kvm",
            "instanceId": f"evaluation-instance:{run_path.name}",
            "generation": "windows-kvm:test",
            "runId": f"evaluation-run:{run_path.name}",
            "phase": "executing",
            "updatedAtNs": 1,
            "security": {"componentId": "ordivon-security", "revision": "test"},
            "baseEnvironmentImageDigest": "sha256:" + "1" * 64,
            "evaluationSpecDigest": "sha256:" + "2" * 64,
            "ownerPid": owner_pid,
            "ownerStartTime": owner_start,
            "runPath": str(run_path),
            "overlayPath": str(run_path / "system-overlay.qcow2"),
            "varsPath": str(run_path / "OVMF_VARS.4m.fd"),
            "runDiskPath": str(run_path / "ordivon-run.img"),
            "qmpPath": str(run_path / "qmp.sock"),
            "tpmSocketPath": str(run_path / "swtpm.sock"),
            "tpmStatePath": str(run_path / "tpm-state"),
            "qemuPid": qemu_pid,
            "qemuStartTime": qemu_start,
            "swtpmPid": 0,
            "swtpmStartTime": None,
            "staged": True,
            "qemuExited": False,
            "qemuExitCode": None,
            "networkDevicePresent": False,
        }

    def test_public_p01_index_preserves_partial_scope(self) -> None:
        path = (
            Path(__file__).parents[2] / "evidence" / "acceptance" / "windows-kvm-p01-bcac3cc.json"
        )
        index = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(index["status"], "partial-acceptance")
        self.assertEqual(index["gates"]["sigkillRecovery"], "passed")
        self.assertEqual(index["gates"]["runtimeRestartRecovery"], "pending")
        self.assertEqual(index["gates"]["wslShutdownRecovery"], "pending")
        self.assertIs(index["scope"]["crashRecoveryFullyAdmitted"], False)
        self.assertIs(index["scope"]["thirdPartyInstallerExecution"], False)

    def test_private_json_replace_is_atomic_and_private(self) -> None:
        path = self.root / "state.json"
        _replace_private_json(path, {"value": 1})
        _replace_private_json(path, {"value": 2})
        self.assertEqual(json.loads(path.read_text()), {"value": 2})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.glob(".state.json.*.tmp")), [])

    def test_reconciler_skips_live_owner(self) -> None:
        run_path = self.state / "runs" / "active"
        run_path.mkdir()
        start = _process_start_time(os.getpid())
        assert start is not None
        _replace_private_json(
            self.state / "run-ledgers" / "active.json",
            self._ledger(run_path, owner_pid=os.getpid(), owner_start=start),
        )
        receipt = self.root / "active-receipt.json"
        result = reconcile_windows_kvm_runs(self.state, receipt_path=receipt)
        self.assertEqual(result["skippedActive"], 1)
        self.assertTrue(run_path.exists())

    def test_reconciler_removes_orphaned_run(self) -> None:
        run_path = self.state / "runs" / "orphan"
        run_path.mkdir()
        (run_path / "system-overlay.qcow2").write_bytes(b"overlay")
        _replace_private_json(
            self.state / "run-ledgers" / "orphan.json",
            self._ledger(run_path),
        )
        result = reconcile_windows_kvm_runs(
            self.state,
            receipt_path=self.root / "orphan-receipt.json",
        )
        self.assertEqual(result["reconciled"], 1)
        self.assertFalse(run_path.exists())

    def test_reconciler_reports_run_without_ledger_without_mutation(self) -> None:
        run_path = self.state / "runs" / "unknown"
        run_path.mkdir()
        result = reconcile_windows_kvm_runs(
            self.state,
            receipt_path=self.root / "unknown-receipt.json",
        )
        self.assertEqual(result["status"], "attention-required")
        self.assertEqual(result["attentionRequired"], 1)
        self.assertTrue(run_path.exists())
        diagnostics = list((self.state / "diagnostics" / "orphan-runs").glob("unknown-*.json"))
        self.assertEqual(len(diagnostics), 1)

    def test_reconciler_removes_orphan_benign_fixture(self) -> None:
        fixture_root = self.state / "fixtures"
        fixture_root.mkdir()
        fixture = fixture_root / "ordivon-benign-v1-run-20.exe"
        fixture.write_bytes(b"fixture")
        result = reconcile_windows_kvm_runs(
            self.state,
            receipt_path=self.root / "fixture-receipt.json",
        )
        self.assertEqual(result["fixtureFilesRemoved"], 1)
        self.assertFalse(fixture.exists())
        self.assertFalse(fixture_root.exists())

    def test_fixture_reconciler_skips_active_run_index(self) -> None:
        fixture_root = self.state / "fixtures"
        fixture_root.mkdir()
        fixture = fixture_root / "ordivon-benign-v1-run-21.exe"
        fixture.write_bytes(b"fixture")
        results, removed, skipped = _reconcile_benign_fixtures(
            fixture_root,
            active_indices={21},
            diagnostics=self.state / "diagnostics" / "orphan-runs",
        )
        self.assertEqual(removed, 0)
        self.assertEqual(skipped, 1)
        self.assertTrue(fixture.exists())
        self.assertEqual(results[0]["decision"], "skipped-active-fixture")

    def test_reconciler_does_not_kill_reused_pid(self) -> None:
        process = subprocess.Popen(["/usr/bin/sleep", "30"])
        try:
            start = _process_start_time(process.pid)
            assert start is not None
            run_path = self.state / "runs" / "reused"
            run_path.mkdir()
            _replace_private_json(
                self.state / "run-ledgers" / "reused.json",
                self._ledger(
                    run_path,
                    qemu_pid=process.pid,
                    qemu_start=start + 1,
                ),
            )
            result = reconcile_windows_kvm_runs(
                self.state,
                receipt_path=self.root / "reused-receipt.json",
            )
            self.assertEqual(result["attentionRequired"], 1)
            self.assertTrue(run_path.exists())
            self.assertTrue((self.state / "run-ledgers" / "reused.json").exists())
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
