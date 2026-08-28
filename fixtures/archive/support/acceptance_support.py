from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ordivon_security._canonical import JsonObject


def write_receipt(path: Path, value: JsonObject) -> None:
    """Atomically replace one deterministic JSON acceptance receipt."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def git_revision(path: Path, label: str) -> str:
    """Return HEAD only for an exact clean Git source tree."""
    if not path.is_dir() or not (path / ".git").exists():
        raise ValueError(f"{label} source is not a Git repository: {path}")
    revision = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    if dirty:
        raise ValueError(f"{label} source tree must be clean")
    return revision
