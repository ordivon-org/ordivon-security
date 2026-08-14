"""V0 attack: the plain boolean gate.

License: free, NO crypto (V0 trusts the tier field as-is).
Gate: render() checks lic.is_pro() directly.

Two one-line forgeries:
  A (file):  rewrite license.json tier -> "pro". Nothing validates it.
  B (memory): flip the tier on the loaded object.

This is the baseline every real product starts above.
"""
from __future__ import annotations

import json
import os
import sys

import features
import license_model as L
import vendor

LEVEL = "V0"
os.environ["TOYDESIGNER_LEVEL"] = LEVEL
LICS = "runs/v0_lic.json"
os.makedirs("runs", exist_ok=True)

vendor.issue("alice", "free", bind=False, expiry=None, out=LICS)

lic = L.load_license(LICS)
features.lic = lic
try:
    features.render.render(2160, 3840)
    print("  unexpected: 4K render allowed at free tier?!")
    sys.exit(1)
except L.NotEntitled:
    print("  gate works at free tier (4K denied)")

# --- attack A: file-level forgery (no signature to break) -------------------
with open(LICS) as f:
    data = json.load(f)
data["tier"] = "pro"
with open(LICS, "w") as f:
    json.dump(data, f, indent=2)
lic2 = L.load_license(LICS)
features.lic = lic2
out = features.render.render(2160, 3840)
print(f"  [ATTACK A] edited license.json tier -> pro : 4K render OK {out}")

# --- attack B: in-memory flip -------------------------------------------------
lic3 = L.load_license(LICS)
lic3.tier = "pro"  # one attribute write; V0 never checks anything
features.lic = lic3
out = features.render.render(2160, 3840)
print(f"  [ATTACK B] runtime tier flip                 : 4K render OK {out}")

print("MEAS v0 plain_flip sites=1 loc=1"
      " -- credential forgery cost: editing one JSON string / one attribute")
print("RESULT ATTACK SUCCEEDED (V0)")
