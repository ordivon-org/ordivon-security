"""V4: signed integrity detects tamper, but the local enforcement decision is patchable."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile

import advanced_ladder as A

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    module = root / "premium.py"
    module.write_text("def run():\n    return 'premium-original'\n", encoding="utf-8")
    manifest = A.build_integrity_manifest(root, ["premium.py"])
    assert A.verify_integrity_manifest(root, manifest)[0]

    module.write_text("def run():\n    return 'premium-local-patch'\n", encoding="utf-8")
    ok, why = A.verify_integrity_manifest(root, manifest)
    assert not ok and "digest-mismatch" in why
    print(f"  [DETECT] changed module rejected: {why}")

    # Attack the local decision, not the vendor signature or manifest.
    original_require = A.require_integrity
    A.require_integrity = lambda root, manifest: None
    try:
        A.require_integrity(root, manifest)
        spec = importlib.util.spec_from_file_location("v4_premium", module)
        assert spec is not None and spec.loader is not None
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
        result = loaded.run()
    finally:
        A.require_integrity = original_require
    assert result == "premium-local-patch"
    print(f"  [PATCH] local integrity enforcement bypassed -> {result}")

print("MEAS v4 integrity detector=effective local_enforcement_patch_sites=1 boundary_changed=false")
print("RESULT LOCAL BYPASS SUCCEEDED (V4)")
