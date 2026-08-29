from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_default_physical_profile.py"


class DefaultPhysicalProfileTests(unittest.TestCase):
    def test_current_owner_machine_satisfies_default_profile(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--profile", "contest-core"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        value = json.loads(completed.stdout)
        self.assertEqual(value["status"], "passed")
        self.assertEqual(value["missing"], [])

    def test_missing_git_fails_closed_independently_of_exact_mingw_paths(self) -> None:
        env = dict(os.environ)
        env["PATH"] = ""
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--profile", "contest-core"],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        value = json.loads(completed.stdout)
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["missing"], ["git"])
        self.assertFalse(value["repositoryUsable"])
        by_name = {item["name"]: item for item in value["executables"]}
        self.assertIsNone(by_name["git"]["path"])
        self.assertTrue(by_name["mingw-gcc"]["executable"])
        self.assertTrue(by_name["mingw-objdump"]["executable"])


if __name__ == "__main__":
    unittest.main()
