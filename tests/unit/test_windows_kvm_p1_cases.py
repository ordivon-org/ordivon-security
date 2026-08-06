from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ordivon_security.evaluation.windows_kvm_p1 import (
    reconcile_windows_kvm_p1_non_executable_media,
)
from ordivon_security.evaluation.windows_kvm_p1_cases import (
    CapabilityCase,
    DerivedCaseManifest,
    materialize_derived_case,
)


class WindowsKvmP1CaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = Path(__file__).parents[2]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _json(self, relative: str) -> dict[str, object]:
        return json.loads((self.repo / relative).read_text(encoding="utf-8"))

    def test_case_a_b_c_keep_host_baseline_read_only(self) -> None:
        case_a = CapabilityCase.from_dict(
            self._json("research/cases/windows-kvm-p1-caseb-case-a-original-repack.json")
        )
        case_b = CapabilityCase.from_dict(
            self._json("research/cases/windows-kvm-p1-caseb-case-b-derived.json")
        )
        case_c = CapabilityCase.from_dict(
            self._json("research/cases/windows-host-p1-caseb-case-c-free-control.json")
        )
        self.assertEqual(case_a.role, "original-repack")
        self.assertEqual(case_b.role, "deweaponized-derived")
        self.assertEqual(case_c.role, "control-free")
        self.assertEqual(case_a.admission.target_surface, "disposable-windows-kvm")
        self.assertEqual(case_b.admission.target_surface, "disposable-windows-kvm")
        self.assertEqual(case_c.admission.target_surface, "windows-host-read-only-baseline")
        self.assertIs(case_c.admission.host_observation_authorized, True)
        self.assertIs(case_c.admission.host_modification_authorized, False)

    def test_case_b_materialization_binds_exact_components(self) -> None:
        manifest = DerivedCaseManifest.from_dict(
            self._json("research/cases/windows-kvm-p1-caseb-case-b-transform.json")
        )
        manifest = replace(manifest, materialization_status="planned", resulting_tree_digest=None)
        sources: dict[str, Path] = {}
        for component in manifest.retained_components:
            source = self.root / component.logical_path.replace("/", "_")
            source.write_bytes(component.logical_path.encode("utf-8"))
            digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
            object.__setattr__(component, "digest", digest)
            object.__setattr__(component, "byte_length", source.stat().st_size)
            sources[component.logical_path] = source
        result = materialize_derived_case(manifest, sources, self.root / "derived")
        self.assertEqual(result["status"], "materialized-private-evaluation-input")
        self.assertIs(result["exportableArtifact"], False)
        self.assertIs(result["hostDeployment"], False)
        for logical in sources:
            self.assertTrue((self.root / "derived" / "payload" / logical).is_file())

    def test_reconcile_removes_only_non_evaluation_media(self) -> None:
        state = self.root / "state"
        media_root = state / "sample-media" / "sample"
        media_root.mkdir(parents=True)
        image = media_root / "installer.ntfs.img"
        image.write_bytes(b"media")
        digest = "sha256:" + hashlib.sha256(image.read_bytes()).hexdigest()
        manifest = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-p1-sample-media",
            "status": "prepared-not-executable",
            "profile": {"executionAuthorized": False},
            "media": {
                "path": str(image),
                "digest": digest,
                "byteLength": image.stat().st_size,
            },
            "executionAuthorized": False,
        }
        (media_root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        receipts = reconcile_windows_kvm_p1_non_executable_media(state, self.root / "receipts")
        self.assertEqual(len(receipts), 1)
        self.assertFalse(media_root.exists())
        self.assertTrue(any((self.root / "receipts").iterdir()))

    def test_observer_resources_cover_required_domains(self) -> None:
        observer = (
            self.repo / "src/ordivon_security/resources/windows_kvm/p1-observer.ps1"
        ).read_text(encoding="utf-8")
        for marker in (
            "Get-CimInstance Win32_Service",
            "Get-CimInstance Win32_SystemDriver",
            "Get-ScheduledTask",
            "Get-BitsTransfer -AllUsers",
            "Get-MpComputerStatus",
            "Get-WinEvent",
            "Get-NetAdapter -IncludeHidden",
        ):
            self.assertIn(marker, observer)


if __name__ == "__main__":
    unittest.main()
