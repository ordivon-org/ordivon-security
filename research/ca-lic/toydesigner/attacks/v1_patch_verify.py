"""V1 attack: the signature is unforgeable, the enforcement is not.

License: free, Ed25519-signed by the vendor. Forging {tier: pro} now FAILS
verification. But the verification is local code, and the tier that gates
actually read is a cached value in the attacker-owned process memory.

Demonstration:
  1) naive forgery        -> REJECTED (signature holds)
  2) patch-the-question   -> patch _check_signature, then load the FORGED
     file: verification passes, gates read tier=pro, everything opens
  3) loader-style flip    -> don't touch any file: flip the cached tier in
     memory after a legit load (the crack-loader equivalent)

The core CA-LIC lesson: credential forgery resistance != enforcement tamper
resistance. The attacker never needed the vendor key.
"""
from __future__ import annotations

import json
import os

import features
import license_model as L
import vendor

LEVEL = "V1"
os.environ["TOYDESIGNER_LEVEL"] = LEVEL
LICS = "runs/v1_lic.json"
FORGED = "runs/v1_forged.json"
os.makedirs("runs", exist_ok=True)

vendor.issue("bob", "free", bind=False, expiry=None, out=LICS)

# --- step 1: naive forgery is rejected --------------------------------------
with open(LICS) as f:
    data = json.load(f)
data["tier"] = "pro"
with open(FORGED, "w") as f:
    json.dump(data, f, indent=2)
forged = L.load_license(FORGED)
ok, why = L.verify_license(forged, LEVEL)
assert not ok, "forged license must NOT verify"
print(f"  [FORGERY] tier flipped in file -> REJECTED ({why})")

# --- step 2: patch the question, then use the forged answer ------------------
orig = L._check_signature
L._check_signature = lambda lic: (True, "patched: signature check removed")
try:
    lic = L.load_license(FORGED)          # the forged file now loads clean
    ok, why = L.verify_license(lic, LEVEL)
    assert ok
    features.lic = lic
    out = features.render.render(2160, 3840)
    print(f"  [PATCH] _check_signature -> True, load forged file : 4K render OK {out}")
    out2 = features.network.multi_node_sync()
    print(f"  [PATCH] multi_node_sync (Pro feature)              : {out2}")
    out3 = features.projects.save_private("toy.toe")
    print(f"  [PATCH] private_toe (Pro feature)                  : {out3}")
finally:
    L._check_signature = orig

# --- step 3: loader-style — flip the cached tier, no file touched ------------
lic3 = L.load_license(LICS)               # legit free license
features.lic = lic3
lic3.tier = "pro"                         # one attribute write in memory
out = features.render.render(2160, 3840)
print(f"  [LOADER] cached tier flip on legit load                : 4K render OK {out}")

print("MEAS v1 patch_verify sites=1 loc=2"
      " -- credential forgery stopped; the local check/cache is the real target")
print("RESULT ATTACK SUCCEEDED (V1)")
