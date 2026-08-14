from __future__ import annotations

from pathlib import Path


def resolve_relative_regular_file(root: Path, relative_path: str, *, label: str) -> Path:
    """Resolve one manifest-owned file without allowing bundle escape or symlink traversal."""

    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{label} root is missing or unsafe")
    relative = Path(relative_path)
    if not relative_path or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path must remain relative to the bundle")

    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError(f"{label} path must not traverse symbolic links")

    if not candidate.is_file():
        raise ValueError(f"{label} file is missing or unsafe")

    root_resolved = root.resolve(strict=True)
    candidate_resolved = candidate.resolve(strict=True)
    if not candidate_resolved.is_relative_to(root_resolved):
        raise ValueError(f"{label} path escapes the bundle")
    return candidate
