from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation.windows_host_p1 import (
    collect_windows_host_resolve_baseline,
)
from ordivon_security.evaluation.windows_kvm_p1 import (
    reconcile_windows_kvm_p1_non_executable_media,
)
from ordivon_security.evaluation.windows_kvm_p1_cases import (
    CapabilityCase,
    DerivedCaseManifest,
    EnvironmentTransformationManifest,
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

    def test_case_a_requires_environment_transformation_manifest(self) -> None:
        manifest = EnvironmentTransformationManifest.from_dict(
            self._json("research/cases/windows-kvm-p1-davinci-case-a-transform.json")
        )
        case_a = CapabilityCase.from_dict(
            self._json("research/cases/windows-kvm-p1-davinci-case-a-original-repack.json")
        )
        self.assertEqual(case_a.role, "original-repack")
        self.assertEqual(case_a.admission.target_surface, "disposable-windows-kvm")
        self.assertIs(manifest.sample_bytes_changed, False)
        self.assertEqual(manifest.materialization_status, "environment-bound")
        self.assertEqual(case_a.transformation_manifest_digest, manifest.digest)
        self.assertIs(case_a.controls["sampleBytesChanged"], False)

    def test_case_b_and_c_target_main_windows_without_open_write_gate(self) -> None:
        case_b = CapabilityCase.from_dict(
            self._json("research/cases/windows-host-p1-davinci-case-b-derived.json")
        )
        case_c = CapabilityCase.from_dict(
            self._json("research/cases/windows-host-p1-davinci-case-c-free-control.json")
        )
        self.assertEqual(case_b.role, "deweaponized-derived")
        self.assertEqual(case_c.role, "control-free")
        self.assertEqual(
            case_b.admission.target_surface,
            "windows-host-controlled-evaluation",
        )
        self.assertEqual(case_c.admission.target_surface, "windows-host-read-only-baseline")
        self.assertIs(case_b.admission.host_observation_authorized, True)
        self.assertIs(case_b.admission.host_modification_authorized, False)
        self.assertIs(case_b.controls["automaticHostMutation"], False)
        self.assertIs(case_c.admission.host_observation_authorized, True)
        self.assertIs(case_c.admission.host_modification_authorized, False)

    def test_case_b_materialization_binds_exact_components(self) -> None:
        manifest = DerivedCaseManifest.from_dict(
            self._json("research/cases/windows-host-p1-davinci-case-b-transform.json")
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
        with self.assertRaisesRegex(ValueError, "mounted Windows volume"):
            materialize_derived_case(manifest, sources, Path("/mnt/c/derived-case"))

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

    def test_host_baseline_wrapper_verifies_read_only_identity(self) -> None:
        powershell = self.root / "powershell.exe"
        script = self.root / "baseline.ps1"
        receipt = self.root / "receipt.json"
        powershell.write_bytes(b"powershell")
        script.write_text("baseline", encoding="utf-8")
        baseline = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-host-resolve-free-baseline",
            "readOnly": True,
            "hostModified": False,
        }
        completed = __import__("subprocess").CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(baseline).encode(), stderr=b""
        )
        fake_identity = ("sha256:" + "1" * 64, 1)
        with (
            patch(
                "ordivon_security.evaluation.windows_host_p1.subprocess.run",
                return_value=completed,
            ),
            patch(
                "ordivon_security.evaluation.windows_host_p1._digest_path",
                return_value=fake_identity,
            ),
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "is_symlink", return_value=False),
        ):
            result = collect_windows_host_resolve_baseline(powershell, script, receipt)
        self.assertEqual(result["status"], "captured-read-only")
        self.assertIs(result["hostModified"], False)
        self.assertTrue(receipt.is_file())

    def test_public_case_c_and_r0_evidence_bind_private_receipts(self) -> None:
        case_c = self._json("research/cases/windows-host-p1-davinci-case-c-free-control.json")
        public_c = self._json("evidence/acceptance/windows-host-p1-davinci-free-baseline-r3.json")
        public_r0 = self._json(
            "evidence/acceptance/windows-kvm-p1-davinci-residual-correction-r0.json"
        )
        self.assertEqual(public_c["status"], "accepted-read-only-baseline")
        self.assertEqual(public_c["edition"]["claim"], "free-user-declared")
        self.assertIs(public_c["edition"]["behaviorallyVerified"], False)
        self.assertTrue(all(public_c["gate"].values()))
        self.assertEqual(
            case_c["evidence"]["publicIndexDigest"],
            canonical_digest(public_c),
        )
        self.assertEqual(public_r0["status"], "corrected-and-removed")
        self.assertIs(public_r0["authority"]["removed"], True)
        self.assertTrue(public_r0["retainedReceipt"]["digest"].startswith("sha256:"))

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
        profile = self._json("research/profiles/windows-host-resolve-capability-p1.json")
        self.assertIs(profile["invariants"]["automaticHostMutation"], False)
        self.assertIs(profile["invariants"]["prePostDiffRequiredForCaseB"], True)
        self.assertIn("residual-closure", profile["eventChannels"])


if __name__ == "__main__":
    unittest.main()
