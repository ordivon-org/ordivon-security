"""V3 attack: scattered enforcement — find every gate, patch every gate.

License: free, V3 verification (signature + binding). The gates are spread
across three modules using three idioms:
  - features/render.py    direct boolean check  (_gate_render_4k)
  - features/network.py   class methods         (License.require_tier/pro)
  - features/projects.py  registry import       (module-level `gate`)

The TD-style denial strings are the discovery key (same technique as
string-xref hunting in 核心库.dll: "This feature requires Pro license.").

Hunt = AST scan for gate call sites. Patch = neutralize each *site's own
binding* (patched registry.gate does NOT disarm projects.py, which imported
the name directly). Report sites found vs lines patched.
"""
from __future__ import annotations

import ast
import os
import pathlib
import sys

import features
import license_model as L
import vendor

LEVEL = "V3"
os.environ["TOYDESIGNER_LEVEL"] = LEVEL
LICS = "runs/v3_lic.json"
os.makedirs("runs", exist_ok=True)

vendor.issue("dave", "free", bind=True, expiry=None, out=LICS)
lic = L.load_license(LICS)
ok, why = L.verify_license(lic, LEVEL)
assert ok, why
features.lic = lic

# sanity: gate holds before the hunt
try:
    features.projects.save_private("toy.toe")
    sys.exit("unexpected: private_toe allowed at free tier?!")
except L.NotEntitled:
    print("  gate holds at free tier (private_toe denied)")

# --------------------------------------------------------------------------
# HUNT: locate gate sites (AST) + strings-hunt (denial messages)
# --------------------------------------------------------------------------
GATE_NAMES = {"gate", "require_tier", "require_pro"}
HERE = pathlib.Path(__file__).resolve().parent
PKG = HERE.parent / "features"   # attacks/ -> toydesigner/features

sites: list[tuple[str, int, str]] = []   # (module, line, call)
for py in sorted(PKG.glob("*.py")):
    tree = ast.parse(py.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else (
                f.id if isinstance(f, ast.Name) else "")
            if name in GATE_NAMES:
                sites.append((py.name, node.lineno, name))

strings_hits = []
for py in sorted(PKG.glob("*.py")):
    for i, line in enumerate(py.read_text().splitlines(), 1):
        if any(k in line for k in ("requires a Pro", "requires a Commercial",
                                   "without a Pro licence")):
            strings_hits.append((py.name, i))

print(f"  HUNT (AST): {len(sites)} gate call sites")
for m, ln, name in sites:
    print(f"    {m}:{ln}  call {name}()")
print(f"  HUNT (strings): {len(strings_hits)} denial-string sites "
      f"(the xref discovery key)")
for m, ln in strings_hits:
    print(f"    {m}:{ln}")

# --------------------------------------------------------------------------
# PATCH: neutralize each site's own binding
# --------------------------------------------------------------------------
import features.projects  # noqa: E402
import features.render  # noqa: E402

patch_targets = []
if any(name == "gate" for _, _, name in sites):
    features.projects.gate = lambda *a, **k: None
    patch_targets.append("features.projects.gate")
if any(name in ("require_tier", "require_pro") for _, _, name in sites):
    L.License.require_tier = lambda self, need, msg: None
    L.License.require_pro = lambda self, msg: None
    patch_targets.append("License.require_tier / require_pro")
# render's direct check function (no named gate call in its AST):
features.render._gate_render_4k = lambda: None
patch_targets.append("features.render._gate_render_4k")

print(f"  PATCH: {len(patch_targets)} sites patched: "
      f"{', '.join(patch_targets)}")

# --------------------------------------------------------------------------
# VERIFY: free license now unlocks everything
# --------------------------------------------------------------------------
results = []
for name, fn in [
    ("render_4k", lambda: features.render.render(2160, 3840)),
    ("shared_memory", features.network.shared_memory),
    ("multi_node_sync", features.network.multi_node_sync),
    ("private_toe", lambda: features.projects.save_private("toy.toe")),
]:
    try:
        results.append((name, True, str(fn())))
    except L.NotEntitled as e:
        results.append((name, False, f"DENIED: {e}"))
for name, ok, det in results:
    print(f"  {'OK ' if ok else 'NO '} {name:<16} {det}")

if not all(ok for _, ok, _ in results):
    sys.exit("hunt incomplete: some gates still closed")
print(f"MEAS v3 hunt_gates sites={len(sites)} strings={len(strings_hits)} "
      f"patches={len(patch_targets)} loc={len(patch_targets) + 2}"
      f" -- effort scales with surface; structure unchanged")
print("RESULT ATTACK SUCCEEDED (V3)")
