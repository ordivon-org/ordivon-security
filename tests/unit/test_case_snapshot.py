from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from ordivon_security.evaluation import (
    CaseExecutionStatus,
    audit_quarantine_tree,
    create_case_snapshot,
    harden_quarantine_tree,
    verify_case_snapshot,
    verify_case_snapshot_against_root,
    write_quarantine_audit,
)


class CaseSnapshotP0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _case_tree(self, name: str, *, private: bool = True) -> Path:
        root = self.root / name
        nested = root / "nested"
        nested.mkdir(parents=True)
        (root / "sample.bin").write_bytes(b"owned-sample-bytes")
        (nested / "report.txt").write_text("observer report\n", encoding="utf-8")
        if private:
            root.chmod(0o700)
            nested.chmod(0o700)
            (root / "sample.bin").chmod(0o600)
            (nested / "report.txt").chmod(0o600)
        return root

    def test_quarantine_audit_is_read_only_and_reports_drift(self) -> None:
        root = self._case_tree("drift", private=False)
        root.chmod(0o755)
        sample = root / "sample.bin"
        sample.chmod(0o755)
        link = root / "sample-link"
        link.symlink_to(sample)
        before = {
            path.relative_to(root).as_posix(): stat.S_IMODE(path.lstat().st_mode)
            for path in (root, sample, link)
        }

        audit = audit_quarantine_tree(root)

        self.assertIs(audit["compliant"], False)
        self.assertEqual(audit["directories"], 2)
        self.assertEqual(audit["files"], 2)
        self.assertEqual(len(audit["nonPrivateDirectories"]), 2)
        self.assertEqual(len(audit["nonPrivateFiles"]), 2)
        self.assertEqual(len(audit["executableFiles"]), 1)
        self.assertEqual(len(audit["symbolicLinks"]), 1)
        after = {
            path.relative_to(root).as_posix(): stat.S_IMODE(path.lstat().st_mode)
            for path in (root, sample, link)
        }
        self.assertEqual(before, after)

        receipt_path = self.root / "receipts" / "audit.json"
        written = write_quarantine_audit(root, receipt_path)
        self.assertEqual(written["compliant"], audit["compliant"])
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        with self.assertRaisesRegex(FileExistsError, "Receipt already exists"):
            write_quarantine_audit(root, receipt_path)

    def test_hardening_then_audit_is_compliant(self) -> None:
        root = self._case_tree("harden", private=False)
        root.chmod(0o755)
        (root / "nested").chmod(0o755)
        (root / "sample.bin").chmod(0o755)
        (root / "nested" / "report.txt").chmod(0o644)

        receipt = harden_quarantine_tree(root)
        audit = audit_quarantine_tree(root)

        self.assertGreater(receipt["changedEntries"], 0)
        self.assertIs(audit["compliant"], True)
        self.assertEqual(audit["nonPrivateDirectories"], [])
        self.assertEqual(audit["nonPrivateFiles"], [])
        self.assertEqual(audit["executableFiles"], [])

    def test_external_uncontrolled_snapshot_requires_limitations(self) -> None:
        root = self._case_tree("uncontrolled")
        with self.assertRaisesRegex(ValueError, "requires explicit limitations"):
            create_case_snapshot(
                root,
                self.root / "snapshot",
                case_id="case:test",
                execution_status=CaseExecutionStatus.EXTERNAL_UNCONTROLLED_EXECUTION,
            )

    def test_snapshot_digest_excludes_root_and_mtime_but_binds_content(self) -> None:
        first = self._case_tree("first")
        second = self._case_tree("second")
        os.utime(second / "sample.bin", ns=(1_000_000_000, 2_000_000_000))
        limitation = ("A local execution occurred outside an admitted disposable-machine backend.",)
        first_bundle = create_case_snapshot(
            first,
            self.root / "snapshots" / "first",
            case_id="case:portable",
            execution_status=CaseExecutionStatus.EXTERNAL_UNCONTROLLED_EXECUTION,
            source_evaluation_run_ids=("evaluation-run:static-reference",),
            limitations=limitation,
        )
        second_bundle = create_case_snapshot(
            second,
            self.root / "snapshots" / "second",
            case_id="case:portable",
            execution_status=CaseExecutionStatus.EXTERNAL_UNCONTROLLED_EXECUTION,
            source_evaluation_run_ids=("evaluation-run:static-reference",),
            limitations=limitation,
        )

        self.assertEqual(first_bundle.manifest_digest, second_bundle.manifest_digest)
        self.assertEqual(verify_case_snapshot(first_bundle.path), first_bundle.manifest_digest)
        self.assertEqual(
            verify_case_snapshot_against_root(first_bundle.path, first),
            first_bundle.manifest_digest,
        )
        self.assertEqual(stat.S_IMODE(first_bundle.path.stat().st_mode), 0o700)
        for path in first_bundle.path.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(b"owned-sample-bytes", path.read_bytes())

        (second / "nested" / "report.txt").write_text("changed report\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "differs from the retained snapshot"):
            verify_case_snapshot_against_root(second_bundle.path, second)

    def test_snapshot_records_policy_drift_without_claiming_control(self) -> None:
        root = self._case_tree("policy-drift")
        executable = root / "sample.bin"
        executable.chmod(0o755)
        bundle = create_case_snapshot(
            root,
            self.root / "policy-snapshot",
            case_id="case:policy-drift",
            execution_status=CaseExecutionStatus.EXTERNAL_UNCONTROLLED_EXECUTION,
            limitations=("The Case contained executable and non-private files.",),
        )
        manifest = json.loads((bundle.path / "case-manifest.json").read_text(encoding="utf-8"))
        self.assertIs(bundle.quarantine_compliant, False)
        self.assertEqual(manifest["quarantinePolicy"]["nonPrivateFileCount"], 1)
        self.assertEqual(manifest["quarantinePolicy"]["executableFileCount"], 1)

    def test_snapshot_rejects_links_and_detects_manifest_tampering(self) -> None:
        linked = self._case_tree("linked")
        (linked / "link").symlink_to(linked / "sample.bin")
        with self.assertRaisesRegex(ValueError, "rejects symbolic links"):
            create_case_snapshot(
                linked,
                self.root / "linked-snapshot",
                case_id="case:linked",
                execution_status=CaseExecutionStatus.STATIC_ONLY,
            )

        root = self._case_tree("tamper")
        bundle = create_case_snapshot(
            root,
            self.root / "tamper-snapshot",
            case_id="case:tamper",
            execution_status=CaseExecutionStatus.STATIC_ONLY,
        )
        manifest_path = bundle.path / "case-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["limitations"] = ["tampered"]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "manifest digest differs"):
            verify_case_snapshot(bundle.path)


if __name__ == "__main__":
    unittest.main()
