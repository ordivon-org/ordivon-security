#!/usr/bin/env python3
"""Verify Security source-checkout or contest-core physical profiles."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def executable(path: str | None) -> bool:
    return path is not None and os.path.isfile(path) and os.access(path, os.X_OK)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("source", "contest-core"), default="source")
    args = parser.parse_args()

    git_path = shutil.which("git")
    rows = [{"name": "git", "path": git_path, "executable": executable(git_path)}]
    missing = [] if rows[0]["executable"] else ["git"]
    repository_usable = False
    revision = None
    if not missing:
        completed = subprocess.run(
            [git_path, "-C", str(ROOT), "rev-parse", "HEAD"],
            check=False, capture_output=True, text=True, timeout=30,
        )
        repository_usable = completed.returncode == 0
        revision = completed.stdout.strip() if repository_usable else None
        if not repository_usable:
            missing.append("git-repository")

    if args.profile == "contest-core":
        for name, path in (
            ("mingw-gcc", "/usr/bin/x86_64-w64-mingw32-gcc"),
            ("mingw-objdump", "/usr/bin/x86_64-w64-mingw32-objdump"),
        ):
            present = executable(path)
            rows.append({"name": name, "path": path, "executable": present})
            if not present:
                missing.append(name)

    document = {
        "schemaVersion": 1,
        "kind": "ordivon.security-physical-test-profile",
        "profile": args.profile,
        "status": "passed" if not missing else "failed",
        "repositoryUsable": repository_usable,
        "revision": revision,
        "executables": rows,
        "missing": missing,
    }
    print(json.dumps(document, sort_keys=True))
    return 0 if not missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
