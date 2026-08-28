from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from ordivon_security.acceptance_support import git_revision, write_receipt


class AcceptanceSupportTests(unittest.TestCase):
    def test_write_receipt_is_deterministic_atomic_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "receipt.json"
            write_receipt(path, {"z": 1, "a": {"b": True}})
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                json.dumps(
                    {"z": 1, "a": {"b": True}},
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
            )
            self.assertFalse(path.with_name(path.name + ".partial").exists())

    def test_git_revision_requires_exact_clean_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "security-test@ordivon.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Ordivon Security Test"],
                check=True,
            )
            (root / "a.txt").write_text("a\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "a.txt"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "fixture"], check=True)
            expected = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(git_revision(root, "fixture"), expected)
            (root / "a.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source tree must be clean"):
                git_revision(root, "fixture")

    def test_git_revision_rejects_non_repository(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "not a Git repository"),
        ):
            git_revision(Path(directory), "fixture")


if __name__ == "__main__":
    unittest.main()
