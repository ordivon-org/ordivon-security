"""Current-tree CA-LIC publication/scope audit.

This is intentionally not a history-rewrite tool. It verifies the current
working publication surface and the user-requested no-Windows scope for this
round; historical Git erasure is a separate repository operation.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = "2aba805e6ffe6c64ce0e0ebafce4240b61ef26a3"


def git(*args: str) -> list[str]:
    out = subprocess.check_output(["git", *args], cwd=ROOT, text=True)
    return [line for line in out.splitlines() if line]


def main() -> int:
    tracked = git("ls-files")
    untracked = git("ls-files", "--others", "--exclude-standard")
    publication_paths = sorted(set(tracked + untracked))
    changed = sorted(set(git("diff", "--name-only", BASE, "--") + untracked))
    tracked_private = [p for p in publication_paths if "/keys/" in p or "/runs/" in p]
    tracked_binary = [
        p for p in publication_paths
        if p.startswith("research/ca-lic/")
        and Path(p).suffix.lower() in {".exe", ".dll", ".msi", ".sys", ".bin"}
    ]
    windows_touched = [
        p for p in changed
        if "windows" in p.lower() or "kvm" in p.lower() or "windows_kvm" in p.lower()
    ]
    offset_hits: list[str] = []
    offset_re = re.compile(r"0x[0-9a-fA-F]{5,}")
    for rel in publication_paths:
        if rel != "docs/CLIENT-AUTHORITY-ENTITLEMENT-CA-LIC.md" and not rel.startswith("research/ca-lic/"):
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for index, line in enumerate(text.splitlines(), 1):
            if offset_re.search(line):
                offset_hits.append(f"{rel}:{index}")

    result = {
        "schemaVersion": 1,
        "kind": "ordivon.security.ca-lic-publication-audit",
        "baseRevision": BASE,
        "currentTree": {
            "trackedPrivateKeyOrRunPaths": tracked_private,
            "trackedBinaryArtifacts": tracked_binary,
            "exactHexOffsetHits": offset_hits,
        },
        "roundScope": {
            "windowsOrKvmPathsTouched": windows_touched,
            "windowsFrozen": not windows_touched,
        },
        "history": {
            "rewritten": False,
            "claim": "current-tree redaction does not erase historical Git objects",
        },
        "passed": not tracked_private and not tracked_binary and not offset_hits and not windows_touched,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
