"""V2 attack: machine binding moves the anchor, not the authority.

License: commercial, Ed25519-signed AND bound to machine A (this host).
The binding value is stored INSIDE the license (cleartext) and the client
*reports its own* system code. Both facts are attacker-usable.

Demonstration:
  1) legit move: run on machine B -> REJECTED ("created with different
     system code") — the binding genuinely stops license sharing
  2) attack: read the anchor from the license file and spoof the client's
     self-report (get_system_code) -> ACCEPTED

Lesson: V2 stops naive copying but not a hostile host: the anchor is a
client-reported value whose expected answer ships in the license itself.
"""
from __future__ import annotations

import os

import features
import license_model as L
import vendor

LEVEL = "V2"
os.environ["TOYDESIGNER_LEVEL"] = LEVEL
LICS = "runs/v2_lic.json"
os.makedirs("runs", exist_ok=True)

# machine A = this host; the license is bound here
vendor.issue("carol", "commercial", bind=True, expiry=None, out=LICS)
lic = L.load_license(LICS)
print(f"  license bound to system code: {lic.system_code}")

# --- step 1: legitimate user on machine B ------------------------------------
real = L.get_system_code
L.get_system_code = lambda: "machine-B-000000000000"
try:
    ok, why = L.verify_license(lic, LEVEL)
    assert not ok
    print(f"  [LEGIT B] machine B tries machine A's license -> REJECTED ({why})")
finally:
    L.get_system_code = real

# --- step 2: attacker on machine B spoofs the self-report --------------------
# the anchor value is right there in the license file
assert lic.system_code is not None
anchor = lic.system_code
L.get_system_code = lambda: anchor
try:
    ok, why = L.verify_license(lic, LEVEL)
    assert ok
    features.lic = lic
    out = features.network.shared_memory()
    print(f"  [ATTACK] spoof get_system_code -> {anchor[:8]}...      : "
          f"shared_memory OK {out}")
finally:
    L.get_system_code = real

print("MEAS v2 spoof_binding sites=1 loc=3"
      " -- anchor is client-reported; expected value ships in the license")
print("RESULT ATTACK SUCCEEDED (V2)")
