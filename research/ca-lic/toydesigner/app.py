"""ToyDesigner app entry: startup verification + capability matrix.

Usage: TOYDESIGNER_LEVEL=V3 python app.py [license.json]

Levels V0..V3 select the verification chain (see license_model.verify_license).
"""
from __future__ import annotations

import os
import sys

import features
import license_model as L


def run_matrix(lic: L.License) -> list[tuple[str, bool, str]]:
    """Try every feature, record (name, allowed, detail)."""
    calls = [
        ("render_720p", lambda: features.render.render(720, 1280)),
        ("render_4k", lambda: features.render.render(2160, 3840)),
        ("shared_memory", features.network.shared_memory),
        ("multi_node_sync", features.network.multi_node_sync),
        ("private_toe", lambda: features.projects.save_private("toy.toe")),
    ]
    out = []
    for name, fn in calls:
        try:
            out.append((name, True, str(fn())))
        except L.NotEntitled as e:
            out.append((name, False, f"DENIED: {e}"))
    return out


def main(argv: list[str]) -> int:
    level = os.environ.get("TOYDESIGNER_LEVEL", "V3")
    path = argv[1] if len(argv) > 1 else "license.json"
    lic = L.load_license(path)
    ok, why = L.verify_license(lic, level)
    if not ok:
        print(f"[toydesigner] LICENSE REJECTED at {level}: {why}")
        return 1
    features.lic = lic
    print(f"[toydesigner] level={level} user={lic.user} tier={lic.type} "
          f"system={lic.system_code or 'portable'}")
    for name, allowed, detail in run_matrix(lic):
        print(f"  {'OK ' if allowed else 'NO '} {name:<16} {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
