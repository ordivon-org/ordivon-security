from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation.models import SampleIdentity
from ordivon_security.evaluation.windows_kvm_p1_derived_base import (
    WindowsKvmP1SealedResource,
    _resource_identity,
)
from ordivon_security.providers.windows_kvm import WindowsKvmBaseImage


def _digest(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsKvmP1DerivedBaseTests(unittest.TestCase):
    def test_shared_images_layout_remains_qemu_traversable(self) -> None:
        source = (
            Path(__file__).parents[2]
            / "src"
            / "ordivon_security"
            / "evaluation"
            / "windows_kvm_p1_derived_base.py"
        ).read_text(encoding="utf-8")
        self.assertIn("images_root.chmod(0o710)", source)
        self.assertIn('shutil.chown(images_root, user="root", group=config.run_group)', source)
        self.assertNotIn("images_root.chmod(0o700)", source)

    def test_sealed_resource_slots_are_fixed_and_unique(self) -> None:
        sample = SampleIdentity.create(
            sha256="sha256:" + "1" * 64,
            byte_length=10,
            media_type="application/octet-stream",
        )
        controller = WindowsKvmP1SealedResource("generic-controller", sample)
        self.assertEqual(
            controller.guest_path,
            "/ProgramData/Ordivon/p1-controller.exe",
        )
        with self.assertRaisesRegex(ValueError, "Unsupported P1 sealed-resource slot"):
            WindowsKvmP1SealedResource("arbitrary-path", sample)
        with self.assertRaisesRegex(ValueError, "slots must be unique"):
            _resource_identity((controller, controller))

    def test_base_loader_validates_explicit_parent_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            parent_image = root / "parent.qcow2"
            parent_image.write_bytes(b"parent")
            parent_vars = root / "parent.vars"
            parent_vars.write_bytes(b"vars")
            parent_manifest = root / "parent.manifest.json"
            parent_environment = "sha256:" + "a" * 64
            parent_value = {
                "schemaVersion": 1,
                "kind": "ordivon.security.windows-kvm-base-image",
                "providerId": "provider:windows-kvm",
                "paths": {
                    "baseImage": str(parent_image),
                    "baseVars": str(parent_vars),
                },
                "digests": {
                    "environmentImage": parent_environment,
                    "sourceIso": "sha256:" + "b" * 64,
                    "baseImage": _digest(parent_image),
                    "baseVars": _digest(parent_vars),
                    "firmwareCode": "sha256:" + "c" * 64,
                    "guestRunner": "sha256:" + "d" * 64,
                },
                "guest": {"status": "ready", "windowsBuild": "10.0.test"},
            }
            parent_manifest.write_text(json.dumps(parent_value), encoding="utf-8")

            child_image = root / "child.qcow2"
            child_image.write_bytes(b"child-overlay")
            child_manifest = root / "child.manifest.json"
            child_value = {
                "schemaVersion": 1,
                "kind": "ordivon.security.windows-kvm-base-image",
                "providerId": "provider:windows-kvm",
                "paths": {
                    "baseImage": str(child_image),
                    "baseVars": str(parent_vars),
                },
                "digests": {
                    "environmentImage": "sha256:" + "e" * 64,
                    "sourceIso": parent_value["digests"]["sourceIso"],
                    "baseImage": _digest(child_image),
                    "baseVars": _digest(parent_vars),
                    "firmwareCode": parent_value["digests"]["firmwareCode"],
                    "guestRunner": parent_value["digests"]["guestRunner"],
                },
                "guest": {"status": "ready-derived", "windowsBuild": "10.0.test"},
                "parent": {
                    "manifestPath": str(parent_manifest),
                    "manifestDigest": canonical_digest(parent_value),
                    "environmentImageDigest": parent_environment,
                    "baseImageDigest": _digest(parent_image),
                    "baseVarsDigest": _digest(parent_vars),
                    "backingBaseImagePath": str(parent_image),
                },
                "sealedResources": [],
            }
            child_manifest.write_text(json.dumps(child_value), encoding="utf-8")
            child = WindowsKvmBaseImage.load(child_manifest)
            self.assertEqual(child.parent_manifest_path, parent_manifest)
            self.assertEqual(child.parent_environment_image_digest, parent_environment)

            parent_image.write_bytes(b"tampered-parent")
            with self.assertRaisesRegex(ValueError, "base image digest differs"):
                WindowsKvmBaseImage.load(child_manifest)

    def test_base_loader_rejects_parent_manifest_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            image = root / "base.qcow2"
            image.write_bytes(b"base")
            vars_path = root / "vars.fd"
            vars_path.write_bytes(b"vars")
            parent_manifest = root / "parent.json"
            parent_value = {
                "schemaVersion": 1,
                "kind": "ordivon.security.windows-kvm-base-image",
                "providerId": "provider:windows-kvm",
                "paths": {"baseImage": str(image), "baseVars": str(vars_path)},
                "digests": {
                    "environmentImage": "sha256:" + "1" * 64,
                    "sourceIso": "sha256:" + "2" * 64,
                    "baseImage": _digest(image),
                    "baseVars": _digest(vars_path),
                    "firmwareCode": "sha256:" + "3" * 64,
                    "guestRunner": "sha256:" + "4" * 64,
                },
                "guest": {"windowsBuild": "10.0.test"},
            }
            parent_manifest.write_text(json.dumps(parent_value), encoding="utf-8")
            child_image = root / "child.qcow2"
            child_image.write_bytes(b"child")
            child_manifest = root / "child.json"
            child_value = {
                **parent_value,
                "paths": {"baseImage": str(child_image), "baseVars": str(vars_path)},
                "digests": {**parent_value["digests"], "baseImage": _digest(child_image)},
                "parent": {
                    "manifestPath": str(parent_manifest),
                    "manifestDigest": "sha256:" + "f" * 64,
                    "environmentImageDigest": parent_value["digests"]["environmentImage"],
                    "baseImageDigest": _digest(image),
                    "baseVarsDigest": _digest(vars_path),
                    "backingBaseImagePath": str(image),
                },
            }
            child_manifest.write_text(json.dumps(child_value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "parent manifest digest differs"):
                WindowsKvmBaseImage.load(child_manifest)


if __name__ == "__main__":
    unittest.main()
