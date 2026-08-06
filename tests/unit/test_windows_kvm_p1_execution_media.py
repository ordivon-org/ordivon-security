from __future__ import annotations

import contextlib
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation.windows_kvm_p1_cases import (
    CapabilityCase,
    EnvironmentTransformationManifest,
)
from ordivon_security.evaluation.windows_kvm_p1_execution_media import (
    WindowsKvmP1ExecutionContract,
    WindowsKvmP1ExecutionMediaConfig,
    _archive_members,
    _scan_execution_tree,
    materialize_windows_kvm_p1_execution_media,
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsKvmP1ExecutionMediaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "sample.7z"
        self.source.write_bytes(b"archive")
        self.case_value = {
            "schemaVersion": 1,
            "kind": "ordivon.security.capability-case",
            "caseId": "case:test:a-original-repack",
            "revision": "3",
            "role": "original-repack",
            "admission": {
                "deploymentAuthorized": False,
                "evaluationAuthorized": True,
                "hostObservationAuthorized": False,
                "hostModificationAuthorized": False,
                "targetSurface": "disposable-windows-kvm",
            },
            "source": {
                "archiveDigest": _digest(self.source),
                "archiveByteLength": self.source.stat().st_size,
                "archiveName": "sample.7z",
            },
            "transformationManifest": "transform.json",
            "transformationManifestDigest": "",
            "observationProfile": "windows-installer-p1",
            "networkMode": "deny-all",
            "status": "execution-media-contract-ready-runner-required",
            "controls": {
                "sampleBytesChanged": False,
                "fakeNetworkService": "local-record-only",
                "unknownSecondaryExecution": "block",
                "destroyOverlayAfterRun": True,
                "realC2": False,
                "exportableArtifact": False,
            },
        }
        self.transform_value = {
            "schemaVersion": 1,
            "kind": "ordivon.security.environment-transformation-manifest",
            "manifestId": "transform:test:case-a",
            "revision": "2",
            "sourceCaseId": "case:test:source",
            "sourceCaseDigest": "sha256:" + "1" * 64,
            "transformations": [
                "attach-source-read-only",
                "host-materialize-read-only-execution-tree",
                "deny-external-network-at-hypervisor",
                "provide-local-record-only-fake-network-boundary",
                "block-unknown-secondary-executable-launch",
                "use-disposable-overlay-and-destroy-after-run",
            ],
            "retainedSample": {
                "digest": _digest(self.source),
                "byteLength": self.source.stat().st_size,
            },
            "sampleBytesChanged": False,
            "materializationStatus": "environment-bound",
            "exportableArtifact": False,
            "hostDeployment": False,
        }
        transform = EnvironmentTransformationManifest.from_dict(self.transform_value)
        self.case_value["transformationManifestDigest"] = transform.digest
        self.case = CapabilityCase.from_dict(self.case_value)
        self.payload_source = self.root / "payload-source"
        (self.payload_source / "Folder").mkdir(parents=True)
        self.installer = self.payload_source / "Installer.exe"
        self.installer.write_bytes(b"installer")
        (self.payload_source / "Folder" / "data.bin").write_bytes(b"data")
        self.contract_value = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-p1-execution-contract",
            "contractId": "contract:test:case-a",
            "revision": "1",
            "caseId": self.case.case_id,
            "caseManifestDigest": canonical_digest(self.case_value),
            "transformationManifestId": transform.manifest_id,
            "transformationManifestDigest": transform.digest,
            "sourceArchive": {
                "digest": _digest(self.source),
                "byteLength": self.source.stat().st_size,
                "name": "sample.7z",
            },
            "installer": {
                "relativePath": "Installer.exe",
                "digest": _digest(self.installer),
                "byteLength": self.installer.stat().st_size,
                "arguments": [],
            },
            "observationProfile": "windows-installer-p1",
            "requiredTransformations": list(transform.transformations),
            "controls": {
                "sourceReadOnly": True,
                "executionMediaReadOnly": True,
                "networkMode": "deny-all-at-hypervisor",
                "knownDestinationBoundary": "loopback-record-only",
                "unknownSecondaryExecution": "block-by-admitted-policy",
                "disposableOverlay": True,
                "destroyOverlayAfterRun": True,
            },
            "authorization": {
                "materializationAuthorized": True,
                "controllerAdmitted": False,
                "executionAuthorized": False,
                "hostModificationAuthorized": False,
                "exportableArtifact": False,
            },
        }
        self.contract = WindowsKvmP1ExecutionContract.from_dict(self.contract_value)
        self.tools: dict[str, Path] = {}
        for name in ("7z", "mkntfs", "ntfs-3g", "umount", "mountpoint", "sync"):
            path = self.root / name
            path.write_text("tool", encoding="utf-8")
            path.chmod(0o755)
            self.tools[name] = path
        self.config = WindowsKvmP1ExecutionMediaConfig(
            state_root=self.root / "state",
            seven_zip_path=self.tools["7z"],
            mkntfs_path=self.tools["mkntfs"],
            ntfs_3g_path=self.tools["ntfs-3g"],
            umount_path=self.tools["umount"],
            mountpoint_path=self.tools["mountpoint"],
            sync_path=self.tools["sync"],
            overhead_mib=128,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_retained_case_a_contract_keeps_execution_closed(self) -> None:
        repo = Path(__file__).parents[2]
        case_value = json.loads(
            (
                repo
                / "research/cases/windows-kvm-p1-caseb-case-a-original-repack.json"
            ).read_text(encoding="utf-8")
        )
        transform_value = json.loads(
            (
                repo / "research/cases/windows-kvm-p1-caseb-case-a-transform.json"
            ).read_text(encoding="utf-8")
        )
        contract_value = json.loads(
            (
                repo / "research/cases/windows-kvm-p1-caseb-case-a-execution.json"
            ).read_text(encoding="utf-8")
        )
        retained_case = CapabilityCase.from_dict(case_value)
        retained_transform = EnvironmentTransformationManifest.from_dict(transform_value)
        retained_contract = WindowsKvmP1ExecutionContract.from_dict(contract_value)
        retained_contract.validate_authority(
            case_value, retained_case, retained_transform
        )
        self.assertIn(
            "host-materialize-read-only-execution-tree",
            retained_transform.transformations,
        )
        self.assertEqual(
            retained_contract.installer_relative_path, "目标产品B Resolve Studio.exe"
        )
        self.assertIs(retained_contract.materialization_authorized, True)
        self.assertIs(retained_contract.controller_admitted, False)
        self.assertIs(retained_contract.execution_authorized, False)

    def test_contract_binds_case_and_keeps_execution_closed(self) -> None:
        transform = EnvironmentTransformationManifest.from_dict(self.transform_value)
        self.contract.validate_authority(self.case_value, self.case, transform)
        value = self.contract.to_dict()
        authorization = value["authorization"]
        assert isinstance(authorization, dict)
        self.assertIs(authorization["materializationAuthorized"], True)
        self.assertIs(authorization["controllerAdmitted"], False)
        self.assertIs(authorization["executionAuthorized"], False)
        opened = json.loads(json.dumps(self.contract_value))
        opened["authorization"]["executionAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "cannot admit"):
            WindowsKvmP1ExecutionContract.from_dict(opened)

    def test_archive_listing_rejects_links_before_extraction(self) -> None:
        listing = b"""----------\nPath = link.txt\nSize = 10\nAttributes = A lrwxrwxrwx\n\n"""
        completed = Mock(returncode=0, stdout=listing, stderr=b"")
        with (
            patch(
                "ordivon_security.evaluation.windows_kvm_p1_execution_media.subprocess.run",
                return_value=completed,
            ),
            self.assertRaisesRegex(ValueError, "link or reparse"),
        ):
            _archive_members(self.source, self.config)

    def test_tree_rejects_symlinks_and_windows_case_collisions(self) -> None:
        tree_root = self.root / "tree"
        tree_root.mkdir()
        (tree_root / "A.txt").write_text("a", encoding="utf-8")
        (tree_root / "a.TXT").write_text("b", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "collide"):
            _scan_execution_tree(tree_root, max_entries=10, max_total_file_bytes=100)
        shutil.rmtree(tree_root)
        tree_root.mkdir()
        target = tree_root / "target"
        target.write_text("x", encoding="utf-8")
        (tree_root / "link").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "link or special"):
            _scan_execution_tree(tree_root, max_entries=10, max_total_file_bytes=100)

    def test_materializer_builds_verified_not_admitted_media(self) -> None:
        transform = EnvironmentTransformationManifest.from_dict(self.transform_value)
        fake_volume = self.root / "fake-volume"
        fake_volume.mkdir()

        def fake_extract(_source: Path, destination: Path, _config: object) -> None:
            shutil.copytree(self.payload_source, destination, dirs_exist_ok=True)

        def fake_format(image: Path, _size: int, _config: object) -> None:
            image.write_bytes(b"ntfs-image")

        @contextlib.contextmanager
        def fake_mount(
            _image: Path, _mount: Path, _config: object, *, read_only: bool
        ) -> object:
            del read_only
            yield fake_volume

        listed = ("Folder/data.bin", "Installer.exe")
        with (
            patch(
                "ordivon_security.evaluation.windows_kvm_p1_execution_media._archive_members",
                return_value=listed,
            ),
            patch(
                "ordivon_security.evaluation.windows_kvm_p1_execution_media._extract_archive",
                side_effect=fake_extract,
            ),
            patch(
                "ordivon_security.evaluation.windows_kvm_p1_execution_media._format_ntfs_image",
                side_effect=fake_format,
            ),
            patch(
                "ordivon_security.evaluation.windows_kvm_p1_execution_media._mounted_ntfs",
                side_effect=fake_mount,
            ),
            patch(
                "ordivon_security.evaluation.windows_kvm_p1_execution_media._run_checked"
            ),
            patch(
                "ordivon_security.evaluation.windows_kvm_p1_execution_media.security_source_identity",
                return_value={
                    "componentId": "ordivon-security",
                    "revision": "git:test",
                    "revisionKind": "git-commit",
                    "packageVersion": "test",
                },
            ),
        ):
            result = materialize_windows_kvm_p1_execution_media(
                self.contract,
                self.case_value,
                self.case,
                transform,
                self.source,
                self.config,
            )
        self.assertEqual(result["status"], "materialized-not-admitted")
        authorization = result["authorization"]
        assert isinstance(authorization, dict)
        self.assertIs(authorization["qemuAttachmentAuthorized"], False)
        self.assertIs(authorization["controllerAdmitted"], False)
        self.assertIs(authorization["executionAuthorized"], False)
        installer = result["installer"]
        assert isinstance(installer, dict)
        self.assertEqual(installer["logicalPath"], "Installer.exe")
        self.assertEqual(result["treeDigest"], canonical_digest(result["tree"]))
        media = result["media"]
        assert isinstance(media, dict)
        self.assertIs(media["readOnly"], True)
        qemu_arguments = media["qemuArguments"]
        assert isinstance(qemu_arguments, list)
        self.assertIn("readonly=on", " ".join(str(item) for item in qemu_arguments))
        self.assertTrue(Path(str(media["path"])).is_file())
        self.assertFalse((Path(str(media["path"])).parent / "extracted.staging").exists())


if __name__ == "__main__":
    unittest.main()
