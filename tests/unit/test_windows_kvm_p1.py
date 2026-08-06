from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ordivon_security.evaluation.windows_kvm_p1 import (
    _P1_INSPECT_ACTION,
    _P1_PREPARE_ACTION,
    WindowsKvmInstallerProfile,
    WindowsKvmP1MediaConfig,
    prepare_windows_kvm_installer_media,
    windows_kvm_p1_sample_disk_arguments,
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsKvmP1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "sample.7z"
        self.source.write_bytes(b"authorized-installer-archive")
        self.profile = WindowsKvmInstallerProfile(
            profile_id="profile:windows-kvm-p1:test",
            revision="1",
            case_id="case:test-installer",
            archive_digest=_digest(self.source),
            archive_byte_length=self.source.stat().st_size,
            archive_name="installer.7z",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _tool(self, name: str, body: str) -> Path:
        path = self.root / name
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_public_目标产品B_media_index_does_not_authorize_execution(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-caseb-media-bcac3cc.json"
        )
        index = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(index["status"], "media-preparation-accepted-execution-not-authorized")
        self.assertIs(index["authorization"]["prepareAuthorizedMedia"], True)
        self.assertIs(index["authorization"]["attachToGuest"], False)
        self.assertIs(index["authorization"]["executeArchiveOrInstaller"], False)
        self.assertEqual(index["gate"]["embeddedReadbackIdentity"], "passed")

    def test_profile_does_not_authorize_execution_by_default(self) -> None:
        value = self.profile.to_dict()
        self.assertEqual(value["permittedActions"], [_P1_PREPARE_ACTION])
        self.assertNotIn(_P1_INSPECT_ACTION, value["permittedActions"])
        self.assertIs(value["executionAuthorized"], False)
        with self.assertRaisesRegex(ValueError, "bind the installer path"):
            replace(self.profile, execution_authorized=True)

    def test_qemu_sample_disk_is_read_only_and_removable(self) -> None:
        args = windows_kvm_p1_sample_disk_arguments(Path("/sample.img"))
        joined = " ".join(args)
        self.assertIn("readonly=on", joined)
        self.assertIn("removable=on", joined)
        self.assertIn("serial=ORDIVON_P1", joined)

    def test_prepare_media_binds_source_and_embedded_bytes(self) -> None:
        mkntfs = self._tool("mkntfs", "exit 0")
        ntfscp = self._tool("ntfscp", "exit 0")
        ntfscat = self._tool("ntfscat", f"cat '{self.source}'")
        with patch(
            "ordivon_security.evaluation.windows_kvm_p1.security_source_identity",
            return_value={
                "componentId": "ordivon-security",
                "revision": "git:test",
                "revisionKind": "git-commit",
                "packageVersion": "test",
            },
        ):
            result = prepare_windows_kvm_installer_media(
                self.profile,
                self.source,
                WindowsKvmP1MediaConfig(
                    state_root=self.root / "state",
                    mkntfs_path=mkntfs,
                    ntfscp_path=ntfscp,
                    ntfscat_path=ntfscat,
                    overhead_mib=128,
                ),
            )
        self.assertEqual(result["status"], "prepared-not-executable")
        self.assertIs(result["executionAuthorized"], False)
        media = result["media"]
        assert isinstance(media, dict)
        self.assertIs(media["readOnly"], True)
        self.assertIs(media["removable"], True)
        self.assertTrue(Path(str(media["path"])).is_file())
        self.assertEqual(result["implementation"]["revision"], "git:test")
        self.assertEqual(set(result["tools"]), {"mkntfs", "ntfscp", "ntfscat"})
        for identity in result["tools"].values():
            self.assertTrue(identity["digest"].startswith("sha256:"))
            self.assertGreater(identity["byteLength"], 0)
        self.assertEqual(
            result["preparationIdentityDigest"],
            __import__(
                "ordivon_security._canonical", fromlist=["canonical_digest"]
            ).canonical_digest(result["preparationIdentity"]),
        )

    def test_prepare_media_rejects_wrong_source_and_cleans_state(self) -> None:
        wrong = self.root / "wrong.7z"
        wrong.write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "differs from the authorized"):
            prepare_windows_kvm_installer_media(
                self.profile,
                wrong,
                WindowsKvmP1MediaConfig(
                    state_root=self.root / "state",
                    mkntfs_path=self._tool("mkntfs2", "exit 0"),
                    ntfscp_path=self._tool("ntfscp2", "exit 0"),
                    ntfscat_path=self._tool("ntfscat2", "exit 0"),
                ),
            )
        self.assertFalse((self.root / "state" / "sample-media").exists())


if __name__ == "__main__":
    unittest.main()
