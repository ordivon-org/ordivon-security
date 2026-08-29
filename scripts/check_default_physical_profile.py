#!/usr/bin/env python3
"""Verify the non-Python executables required by the default Security test profile."""

from __future__ import annotations

import json
import os
import shutil


def main() -> int:
    requirements = (
        ("git", shutil.which("git")),
        ("mingw-gcc", "/usr/bin/x86_64-w64-mingw32-gcc"),
        ("mingw-objdump", "/usr/bin/x86_64-w64-mingw32-objdump"),
    )
    rows = []
    missing = []
    for name, path in requirements:
        executable = path is not None and os.path.isfile(path) and os.access(path, os.X_OK)
        rows.append({"name": name, "path": path, "executable": executable})
        if not executable:
            missing.append(name)
    document = {
        "schemaVersion": 1,
        "kind": "ordivon.security-default-physical-test-profile",
        "status": "passed" if not missing else "failed",
        "executables": rows,
        "missing": missing,
    }
    print(json.dumps(document, sort_keys=True))
    return 0 if not missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
